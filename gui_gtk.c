/* gui_gtk.c -- GTK3 wrapper for secure-file-manager backend */

#include <gtk/gtk.h>
#include "src/crypto.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define VAULT_DIR ".vault"
#define MAX_DIGEST_SIZE 64
#define HEX_BUF_SIZE (MAX_DIGEST_SIZE * 2 + 1)

static GtkWidget *password_entry;
static GtkWidget *vault_list;
static GtkWidget *hash_output;

/* Function declarations */
static void populate_vault_list();
static void refresh_vault_list();

/* ---------------- Vault functions ---------------- */
static void refresh_vault_list()
{
    populate_vault_list();
}

static void on_add_file(GtkWidget *btn, gpointer user_data)
{
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Select file to add to vault", NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
    {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        const char *pw = gtk_entry_get_text(GTK_ENTRY(password_entry));
        if (!pw || !pw[0])
        {
            g_printerr("Enter a password first.\n");
            g_free(filename);
            gtk_widget_destroy(dialog);
            return;
        }

        mkdir(VAULT_DIR, 0700);
        char outpath[1024];
        const char *base = g_path_get_basename(filename);
        snprintf(outpath, sizeof(outpath), "%s/%s.enc", VAULT_DIR, base);

        if (encrypt_file(filename, outpath, pw))
            g_print("Added to vault: %s\n", outpath);
        else
            g_printerr("Encryption failed for %s\n", filename);

        g_free(filename);
    }
    gtk_widget_destroy(dialog);
    refresh_vault_list();
}

static void on_retrieve_file(GtkWidget *btn, gpointer user_data)
{
    GtkListBoxRow *row = gtk_list_box_get_selected_row(GTK_LIST_BOX(vault_list));
    if (!row)
        return;

    GtkWidget *child = gtk_bin_get_child(GTK_BIN(row));
    const char *vault_name = gtk_label_get_text(GTK_LABEL(child));

    char vault_path[1024];
    snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, vault_name);

    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Save decrypted file as", NULL, GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
    {
        char *out = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        const char *pw = gtk_entry_get_text(GTK_ENTRY(password_entry));
        if (!pw || !pw[0])
        {
            g_printerr("Enter a password first.\n");
            g_free(out);
            gtk_widget_destroy(dialog);
            return;
        }

        if (decrypt_file(vault_path, out, pw))
            g_print("Retrieved: %s -> %s\n", vault_path, out);
        else
            g_printerr("Decryption failed: %s\n", vault_path);

        g_free(out);
    }
    gtk_widget_destroy(dialog);
}

static void on_delete_file(GtkWidget *btn, gpointer user_data)
{
    GtkListBoxRow *row = gtk_list_box_get_selected_row(GTK_LIST_BOX(vault_list));
    if (!row)
        return;

    GtkWidget *child = gtk_bin_get_child(GTK_BIN(row));
    const char *vault_name = gtk_label_get_text(GTK_LABEL(child));

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", VAULT_DIR, vault_name);

    if (remove(path) == 0)
    {
        g_print("Deleted: %s\n", path);
        refresh_vault_list();
    }
    else
        g_printerr("Failed to delete %s\n", path);
}

/* ---------------- Arbitrary encrypt/decrypt ---------------- */
static void on_encrypt_file(GtkWidget *btn, gpointer user_data)
{
    GtkWidget *od = gtk_file_chooser_dialog_new(
        "Select file to encrypt", NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(od)) != GTK_RESPONSE_ACCEPT)
    {
        gtk_widget_destroy(od);
        return;
    }
    char *in = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(od));
    gtk_widget_destroy(od);

    GtkWidget *sd = gtk_file_chooser_dialog_new(
        "Save encrypted file as", NULL, GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(sd)) == GTK_RESPONSE_ACCEPT)
    {
        char *out = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(sd));
        const char *pw = gtk_entry_get_text(GTK_ENTRY(password_entry));
        if (!pw)
            pw = "";

        if (encrypt_file(in, out, pw))
            g_print("Encrypted: %s -> %s\n", in, out);
        else
            g_printerr("Encryption failed: %s\n", in);

        g_free(out);
    }
    g_free(in);
    gtk_widget_destroy(sd);
}

static void on_decrypt_file(GtkWidget *btn, gpointer user_data)
{
    GtkWidget *od = gtk_file_chooser_dialog_new(
        "Select file to decrypt", NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(od)) != GTK_RESPONSE_ACCEPT)
    {
        gtk_widget_destroy(od);
        return;
    }
    char *in = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(od));
    gtk_widget_destroy(od);

    GtkWidget *sd = gtk_file_chooser_dialog_new(
        "Save decrypted file as", NULL, GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(sd)) == GTK_RESPONSE_ACCEPT)
    {
        char *out = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(sd));
        const char *pw = gtk_entry_get_text(GTK_ENTRY(password_entry));
        if (!pw)
            pw = "";

        if (decrypt_file(in, out, pw))
            g_print("Decrypted: %s -> %s\n", in, out);
        else
            g_printerr("Decryption failed: %s\n", in);

        g_free(out);
    }
    g_free(in);
    gtk_widget_destroy(sd);
}

/* ---------------- Hash file ---------------- */
static void on_hash_file(GtkWidget *btn, gpointer user_data)
{
    GtkWidget *fd = gtk_file_chooser_dialog_new(
        "Select file to hash", NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(fd)) != GTK_RESPONSE_ACCEPT)
    {
        gtk_widget_destroy(fd);
        return;
    }
    char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fd));
    gtk_widget_destroy(fd);

    unsigned char outbuf[MAX_DIGEST_SIZE];
    memset(outbuf, 0, sizeof(outbuf));
    unsigned int outlen = 0;

    if (hash_file("sha256", filename, outbuf, &outlen) == 1)
    {
        char hex[HEX_BUF_SIZE];
        if (outlen > MAX_DIGEST_SIZE)
            outlen = MAX_DIGEST_SIZE;
        for (unsigned int i = 0; i < outlen; i++)
            sprintf(&hex[i * 2], "%02x", outbuf[i]);
        hex[outlen * 2] = '\0';

        GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(hash_output));
        gtk_text_buffer_set_text(tb, hex, -1);
    }
    else
    {
        GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(hash_output));
        gtk_text_buffer_set_text(tb, "Hash failed", -1);
    }

    g_free(filename);
}

/* ---------------- Vault population ---------------- */
static void populate_vault_list()
{
    GList *children = gtk_container_get_children(GTK_CONTAINER(vault_list));
    for (GList *l = children; l != NULL; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);

    GDir *d = g_dir_open(VAULT_DIR, 0, NULL);
    if (!d)
        return;

    const char *name;
    while ((name = g_dir_read_name(d)))
    {
        if (g_str_has_suffix(name, ".enc"))
        {
            GtkWidget *label = gtk_label_new(name);
            GtkWidget *row = gtk_list_box_row_new();
            gtk_container_add(GTK_CONTAINER(row), label);
            gtk_widget_show_all(row);
            gtk_list_box_insert(GTK_LIST_BOX(vault_list), row, -1);
        }
    }
    g_dir_close(d);
}

/* ---------------- Main ---------------- */
int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Secure File Manager (GTK3)");
    gtk_window_set_default_size(GTK_WINDOW(win), 700, 500);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *grid = gtk_grid_new();
    gtk_container_set_border_width(GTK_CONTAINER(grid), 8);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_container_add(GTK_CONTAINER(win), grid);

    /* Password entry */
    /* Password entry default example */
    password_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry),
                                   "Password (used for encrypt/decrypt/vault)");
    // Set a default password
    gtk_entry_set_text(GTK_ENTRY(password_entry), "mypassword123");
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE); // mask input
    gtk_grid_attach(GTK_GRID(grid), password_entry, 0, 0, 2, 1);

    /* Vault list and buttons */
    vault_list = gtk_list_box_new();
    gtk_widget_set_size_request(vault_list, 300, 200);
    gtk_grid_attach(GTK_GRID(grid), vault_list, 0, 1, 1, 4);

    GtkWidget *add_btn = gtk_button_new_with_label("Add to Vault");
    GtkWidget *retrieve_btn = gtk_button_new_with_label("Retrieve");
    GtkWidget *delete_btn = gtk_button_new_with_label("Delete");
    gtk_grid_attach(GTK_GRID(grid), add_btn, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), retrieve_btn, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), delete_btn, 1, 3, 1, 1);

    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_add_file), NULL);
    g_signal_connect(retrieve_btn, "clicked", G_CALLBACK(on_retrieve_file), NULL);
    g_signal_connect(delete_btn, "clicked", G_CALLBACK(on_delete_file), NULL);

    /* Encrypt/decrypt buttons */
    GtkWidget *enc_btn = gtk_button_new_with_label("Encrypt File...");
    GtkWidget *dec_btn = gtk_button_new_with_label("Decrypt File...");
    gtk_grid_attach(GTK_GRID(grid), enc_btn, 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), dec_btn, 1, 5, 1, 1);
    g_signal_connect(enc_btn, "clicked", G_CALLBACK(on_encrypt_file), NULL);
    g_signal_connect(dec_btn, "clicked", G_CALLBACK(on_decrypt_file), NULL);

    /* Hash */
    GtkWidget *hash_btn = gtk_button_new_with_label("Hash File (SHA-256)");
    gtk_grid_attach(GTK_GRID(grid), hash_btn, 0, 6, 2, 1);
    g_signal_connect(hash_btn, "clicked", G_CALLBACK(on_hash_file), NULL);

    hash_output = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(hash_output), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(hash_output), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(hash_output), GTK_WRAP_WORD_CHAR);
    /* selectable by default in GTK3 if not editable */
    gtk_widget_set_size_request(hash_output, 600, 120);
    gtk_grid_attach(GTK_GRID(grid), hash_output, 0, 7, 2, 1);

    /* Populate vault list */
    populate_vault_list();

    gtk_widget_show_all(win);
    gtk_main();

    return 0;
}
