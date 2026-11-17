/* GTK3 native interface. Only the main thread touches widgets. */
#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <string.h>
#include "src/crypto.h"
#include "src/file_manager.h"
#include "src/gui_style.h"

enum { NAME, DISPLAY, FORMAT, SIZE, MODIFIED, BYTES, MTIME, ICON, MODERN, NCOLS };
typedef enum { IMPORT, EXPORT, REMOVE, ENCRYPT, DECRYPT, HASH } Operation;
typedef struct {
    Operation op;
    GPtrArray *paths;
    char *output, *password, *algorithm, *expected, *digest;
    gboolean legacy;
    unsigned succeeded, failed;
    GString *errors;
} Job;
typedef struct {
    char *name, *display, *format, *size, *date;
    guint64 bytes;
    gint64 mtime;
    gboolean modern;
} Item;
typedef struct {
    GPtrArray *items;
    guint64 bytes;
    unsigned legacy;
    char *error;
} Snapshot;
static struct {
    GtkWidget *window, *pages, *nav[3], *vault_pages, *tree, *search;
    GtkWidget *count, *storage, *protection, *count_label, *selected_label;
    GtkWidget *add, *export, *remove, *refresh, *encrypt, *decrypt, *hash;
    GtkWidget *algorithm, *file, *expected, *digest, *hash_status, *copy;
    GtkWidget *activity, *activity_empty, *info, *info_label, *status, *spinner;
    GtkListStore *store;
    GtkTreeModel *filter, *sorted;
    GFileMonitor *monitor;
    gboolean busy, scanning, refresh_again;
    guint refresh_source, activity_count;
    char *query, *digest_text;
} app;

static void refresh_vault(void);
static void on_add(GtkWidget *, gpointer);
static void on_export(GtkWidget *, gpointer);
static void on_remove(GtkWidget *, gpointer);
static void on_manual(GtkWidget *, gpointer);
static void on_hash(GtkWidget *, gpointer);
static void cls(GtkWidget *w, const char *name) {
    gtk_style_context_add_class(gtk_widget_get_style_context(w), name);
}
static GtkWidget *box(GtkOrientation o, int spacing) { return gtk_box_new(o, spacing); }
static void pack(GtkWidget *b, GtkWidget *w, gboolean expand) {
    gtk_box_pack_start(GTK_BOX(b), w, expand, expand, 0);
}
static GtkWidget *text(const char *value, const char *style) {
    GtkWidget *w = gtk_label_new(value);
    gtk_label_set_xalign(GTK_LABEL(w), 0);
    if (style)
        cls(w, style);
    return w;
}
static GtkWidget *button(const char *name, const char *icon, const char *style, GCallback cb,
                         gpointer data) {
    GtkWidget *w = gtk_button_new_with_label(name);
    if (icon) {
        gtk_button_set_image(GTK_BUTTON(w),
                             gtk_image_new_from_icon_name(icon, GTK_ICON_SIZE_BUTTON));
        gtk_button_set_always_show_image(GTK_BUTTON(w), TRUE);
    }
    if (style)
        cls(w, style);
    if (cb)
        g_signal_connect(w, "clicked", cb, data);
    return w;
}
static void notice(GtkMessageType type, const char *message) {
    gtk_info_bar_set_message_type(GTK_INFO_BAR(app.info), type);
    gtk_label_set_text(GTK_LABEL(app.info_label), message);
    gtk_widget_show(app.info);
}
static void dismiss(GtkInfoBar *bar, gint response, gpointer data) {
    (void)response;
    (void)data;
    gtk_widget_hide(GTK_WIDGET(bar));
}
static void status(const char *message) { gtk_label_set_text(GTK_LABEL(app.status), message); }
static char *selected(gboolean *modern) {
    GtkTreeIter iter;
    GtkTreeModel *model;
    char *name = NULL;
    if (gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(app.tree)),
                                        &model, &iter))
        gtk_tree_model_get(model, &iter, NAME, &name, MODERN, modern, -1);
    return name;
}
static void actions(void) {
    gboolean modern;
    char *name = selected(&modern);
    GtkWidget *all[] = {app.add, app.encrypt, app.decrypt, app.hash};
    for (unsigned i = 0; i < G_N_ELEMENTS(all); i++)
        gtk_widget_set_sensitive(all[i], !app.busy);
    gtk_widget_set_sensitive(app.file, !app.busy);
    gtk_widget_set_sensitive(app.algorithm, !app.busy);
    gtk_widget_set_sensitive(app.expected, !app.busy);
    gtk_widget_set_sensitive(app.refresh, !app.busy && !app.scanning);
    gtk_widget_set_sensitive(app.export, !app.busy && name != NULL);
    gtk_widget_set_sensitive(app.remove, !app.busy && name != NULL);
    g_free(name);
}
static void selection_changed(GtkTreeSelection *selection, gpointer data) {
    (void)selection;
    (void)data;
    gboolean modern;
    char *name = selected(&modern);
    char *display =
        name ? g_filename_display_name(name) : g_strdup("Select a file to export or remove");
    gtk_label_set_text(GTK_LABEL(app.selected_label), display);
    g_free(display);
    g_free(name);
    actions();
}
static void log_activity(const char *message, gboolean success) {
    GtkWidget *row = box(GTK_ORIENTATION_HORIZONTAL, 12);
    cls(row, "activity-row");
    GtkWidget *icon = gtk_image_new_from_icon_name(
        success ? "object-select-symbolic" : "dialog-warning-symbolic", GTK_ICON_SIZE_BUTTON);
    cls(icon, success ? "success" : "error");
    pack(row, icon, FALSE);
    GtkWidget *label = text(message, NULL);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    pack(row, label, TRUE);
    GDateTime *now = g_date_time_new_now_local();
    char *stamp = g_date_time_format(now, "%H:%M");
    pack(row, text(stamp, "muted"), FALSE);
    g_free(stamp);
    g_date_time_unref(now);
    gtk_list_box_insert(GTK_LIST_BOX(app.activity), row, 0);
    gtk_widget_show_all(row);
    gtk_widget_hide(app.activity_empty);
    if (++app.activity_count > 100) {
        GtkListBoxRow *last = gtk_list_box_get_row_at_index(GTK_LIST_BOX(app.activity), 100);
        if (last)
            gtk_widget_destroy(GTK_WIDGET(last));
        app.activity_count = 100;
    }
}

/* Passwords are requested per operation and copied only into its worker. */
typedef struct {
    GtkWidget *dialog, *entry, *confirm, *hint, *meter;
    gboolean creating;
} Prompt;
static void password_changed(GtkEditable *editable, gpointer data) {
    (void)editable;
    Prompt *p = data;
    const char *value = gtk_entry_get_text(GTK_ENTRY(p->entry));
    glong n = g_utf8_strlen(value, -1);
    gboolean valid = n > 0;
    if (p->creating) {
        valid = n >= 12 && strcmp(value, gtk_entry_get_text(GTK_ENTRY(p->confirm))) == 0;
        gtk_level_bar_set_value(GTK_LEVEL_BAR(p->meter), MIN(n, 24));
        gtk_label_set_text(
            GTK_LABEL(p->hint),
            n < 12 ? "Use at least 12 characters. A unique passphrase is best."
                   : (valid ? "Passwords match. Keep a safe copy; recovery is not possible."
                            : "Enter the same password in both fields."));
    }
    gtk_dialog_set_response_sensitive(GTK_DIALOG(p->dialog), GTK_RESPONSE_ACCEPT, valid);
}
static void password_visible(GtkToggleButton *toggle, gpointer data) {
    Prompt *p = data;
    gboolean show = gtk_toggle_button_get_active(toggle);
    gtk_entry_set_visibility(GTK_ENTRY(p->entry), show);
    if (p->confirm)
        gtk_entry_set_visibility(GTK_ENTRY(p->confirm), show);
}
static void generate_password(GtkWidget *widget, gpointer data) {
    (void)widget;
    Prompt *p = data;
    unsigned char bytes[16];
    char value[33];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        gtk_label_set_text(GTK_LABEL(p->hint),
                           "Secure randomness unavailable. Please enter a passphrase.");
        return;
    }
    for (unsigned i = 0; i < sizeof(bytes); i++)
        g_snprintf(value + 2 * i, 3, "%02x", bytes[i]);
    gtk_entry_set_text(GTK_ENTRY(p->entry), value);
    gtk_entry_set_text(GTK_ENTRY(p->confirm), value);
    OPENSSL_cleanse(bytes, sizeof(bytes));
    OPENSSL_cleanse(value, sizeof(value));
}
static char *password_prompt(const char *title, gboolean creating) {
    Prompt p = {0};
    p.creating = creating;
    p.dialog = gtk_dialog_new_with_buttons(
        title, GTK_WINDOW(app.window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "Cancel",
        GTK_RESPONSE_CANCEL, creating ? "Encrypt files" : "Continue", GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(p.dialog), 490, -1);
    gtk_dialog_set_default_response(GTK_DIALOG(p.dialog), GTK_RESPONSE_ACCEPT);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(p.dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 24);
    gtk_box_set_spacing(GTK_BOX(content), 12);
    pack(content,
         text(creating ? "Choose a password for these files" : "Enter this file's password",
              "section"),
         FALSE);
    GtkWidget *note =
        text(creating ? "Each file is encrypted independently. Store your password safely."
                      : "The password is used only for this operation.",
             "subtitle");
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    pack(content, note, FALSE);
    p.entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(p.entry), "Password");
    gtk_entry_set_visibility(GTK_ENTRY(p.entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(p.entry), TRUE);
    gtk_entry_set_input_purpose(GTK_ENTRY(p.entry), GTK_INPUT_PURPOSE_PASSWORD);
    pack(content, p.entry, FALSE);
    if (creating) {
        p.confirm = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(p.confirm), "Confirm password");
        gtk_entry_set_visibility(GTK_ENTRY(p.confirm), FALSE);
        gtk_entry_set_activates_default(GTK_ENTRY(p.confirm), TRUE);
        gtk_entry_set_input_purpose(GTK_ENTRY(p.confirm), GTK_INPUT_PURPOSE_PASSWORD);
        pack(content, p.confirm, FALSE);
        p.meter = gtk_level_bar_new_for_interval(0, 24);
        pack(content, p.meter, FALSE);
        p.hint = text("Use at least 12 characters. A unique passphrase is best.", "muted");
        gtk_label_set_line_wrap(GTK_LABEL(p.hint), TRUE);
        pack(content, p.hint, FALSE);
        g_signal_connect(p.confirm, "changed", G_CALLBACK(password_changed), &p);
    }
    GtkWidget *options = box(GTK_ORIENTATION_HORIZONTAL, 12),
              *show = gtk_check_button_new_with_label("Show password");
    pack(options, show, TRUE);
    g_signal_connect(show, "toggled", G_CALLBACK(password_visible), &p);
    if (creating)
        pack(options,
             button("Generate", "view-refresh-symbolic", NULL, G_CALLBACK(generate_password), &p),
             FALSE);
    pack(content, options, FALSE);
    g_signal_connect(p.entry, "changed", G_CALLBACK(password_changed), &p);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(p.dialog), GTK_RESPONSE_ACCEPT, FALSE);
    cls(gtk_dialog_get_widget_for_response(GTK_DIALOG(p.dialog), GTK_RESPONSE_ACCEPT), "primary");
    gtk_widget_show_all(p.dialog);
    gtk_widget_grab_focus(p.entry);
    char *result = NULL;
    if (gtk_dialog_run(GTK_DIALOG(p.dialog)) == GTK_RESPONSE_ACCEPT)
        result = g_strdup(gtk_entry_get_text(GTK_ENTRY(p.entry)));
    gtk_entry_set_text(GTK_ENTRY(p.entry), "");
    if (p.confirm)
        gtk_entry_set_text(GTK_ENTRY(p.confirm), "");
    gtk_widget_destroy(p.dialog);
    return result;
}
static char *choose(const char *title, GtkFileChooserAction mode, const char *suggested) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        title, GTK_WINDOW(app.window), mode, "Cancel", GTK_RESPONSE_CANCEL,
        mode == GTK_FILE_CHOOSER_ACTION_SAVE ? "Save" : "Open", GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 880, 580);
    if (suggested && mode == GTK_FILE_CHOOSER_ACTION_SAVE)
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), suggested);
    char *result = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
        result = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    gtk_widget_destroy(dialog);
    return result;
}
static gboolean legacy_consent(void) {
    GtkWidget *d =
        gtk_message_dialog_new(GTK_WINDOW(app.window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
                               GTK_BUTTONS_NONE, "Read an older CBC file?");
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(d),
        "Legacy encryption cannot detect every modification or reliably confirm a password. Check "
        "recovered contents before using them. Export and re-import files to upgrade protection.");
    gtk_dialog_add_buttons(GTK_DIALOG(d), "Cancel", GTK_RESPONSE_CANCEL,
                           "Continue with legacy file", GTK_RESPONSE_ACCEPT, NULL);
    int response = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    return response == GTK_RESPONSE_ACCEPT;
}
static gboolean has_modern_magic(const char *path) {
    GFile *input = g_file_new_for_path(path);
    GFileInfo *info = g_file_query_info(input, "standard::type,standard::is-symlink",
                                        G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
    g_object_unref(input);
    gboolean regular = info && g_file_info_get_file_type(info) == G_FILE_TYPE_REGULAR &&
                       !g_file_info_get_is_symlink(info);
    g_clear_object(&info);
    if (!regular)
        return FALSE;
    FILE *file = g_fopen(path, "rb");
    unsigned char magic[8];
    gboolean modern = file && fread(magic, 1, 8, file) == 8 && memcmp(magic, "SFMENC\r\n", 8) == 0;
    if (file)
        fclose(file);
    return modern;
}
static Job *job_new(Operation op) {
    Job *j = g_new0(Job, 1);
    j->op = op;
    j->paths = g_ptr_array_new_with_free_func(g_free);
    j->errors = g_string_new(NULL);
    return j;
}
static void job_free(gpointer data) {
    Job *j = data;
    if (j->password) {
        OPENSSL_cleanse(j->password, strlen(j->password));
        g_free(j->password);
    }
    g_ptr_array_unref(j->paths);
    g_string_free(j->errors, TRUE);
    g_free(j->output);
    g_free(j->algorithm);
    g_free(j->expected);
    g_free(j->digest);
    g_free(j);
}
static void work(GTask *task, gpointer source, gpointer data, GCancellable *cancel) {
    (void)source;
    (void)cancel;
    Job *j = data;
    for (guint i = 0; i < j->paths->len; i++) {
        const char *path = g_ptr_array_index(j->paths, i), *error = NULL;
        int ok = 0;
        switch (j->op) {
        case IMPORT:
            ok = add_file_to_vault(path, j->password);
            error = vault_last_error();
            break;
        case EXPORT:
            ok = j->legacy ? retrieve_legacy_file_from_vault(path, j->output, j->password)
                           : retrieve_file_from_vault(path, j->output, j->password);
            error = vault_last_error();
            break;
        case REMOVE:
            ok = j->legacy ? delete_legacy_file_from_vault(path, j->password)
                           : delete_file_from_vault(path, j->password);
            error = vault_last_error();
            break;
        case ENCRYPT:
            ok = encrypt_file(path, j->output, j->password);
            error = crypto_last_error();
            break;
        case DECRYPT:
            ok = j->legacy ? decrypt_legacy_file(path, j->output, j->password)
                           : decrypt_file(path, j->output, j->password);
            error = crypto_last_error();
            break;
        case HASH: {
            unsigned char digest[64];
            unsigned length = 0;
            ok = hash_file(j->algorithm, path, digest, &length);
            error = crypto_last_error();
            if (ok) {
                j->digest = g_malloc(length * 2 + 1);
                for (unsigned k = 0; k < length; k++)
                    g_snprintf(j->digest + 2 * k, 3, "%02x", digest[k]);
            }
            break;
        }
        }
        if (ok)
            j->succeeded++;
        else {
            j->failed++;
            if (j->failed <= 6) {
                char *base = g_path_get_basename(path), *display = g_filename_display_name(base),
                     *safe = g_utf8_make_valid(error ? error : "Operation failed", -1);
                g_string_append_printf(j->errors, "%s%s: %s", j->errors->len ? "\n" : "", display,
                                       safe);
                g_free(base);
                g_free(display);
                g_free(safe);
            }
        }
    }
    if (j->password) {
        OPENSSL_cleanse(j->password, strlen(j->password));
        g_clear_pointer(&j->password, g_free);
    }
    g_task_return_boolean(task, j->failed == 0);
}
static void finished(GObject *source, GAsyncResult *result, gpointer data) {
    (void)source;
    (void)data;
    GTask *task = G_TASK(result);
    Job *j = g_task_get_task_data(task);
    (void)g_task_propagate_boolean(task, NULL);
    const char *verbs[] = {"Imported", "Exported", "Removed", "Encrypted", "Decrypted", "Hashed"};
    char *summary =
        g_strdup_printf("%s %u file%s%s", verbs[j->op], j->succeeded, j->succeeded == 1 ? "" : "s",
                        j->failed ? "; some files could not be processed." : " successfully.");
    app.busy = FALSE;
    gtk_spinner_stop(GTK_SPINNER(app.spinner));
    gtk_widget_hide(app.spinner);
    if (j->op == HASH && j->digest) {
        g_free(app.digest_text);
        app.digest_text = g_strdup(j->digest);
        gtk_label_set_text(GTK_LABEL(app.digest), j->digest);
        gtk_widget_set_sensitive(app.copy, TRUE);
        gboolean match = !j->expected || g_ascii_strcasecmp(j->expected, j->digest) == 0;
        const char *message =
            !j->expected ? "Checksum ready. Compare it with a checksum from a trusted source."
                         : (match ? "Checksums match. The file matches the supplied checksum."
                                  : "Checksum mismatch. Verify the file's source before using it.");
        gtk_label_set_text(GTK_LABEL(app.hash_status), message);
        notice(match ? GTK_MESSAGE_INFO : GTK_MESSAGE_WARNING, message);
        log_activity(message, match);
    } else {
        log_activity(summary, !j->failed);
        char *message = j->failed
                            ? g_strdup_printf("%s\n%s%s", summary, j->errors->str,
                                              j->failed > 6 ? "\nAdditional failures omitted." : "")
                            : g_strdup(summary);
        notice(j->failed ? GTK_MESSAGE_ERROR : GTK_MESSAGE_INFO, message);
        g_free(message);
        if (j->op == HASH)
            gtk_label_set_text(GTK_LABEL(app.hash_status),
                               "Could not calculate checksum. Check the error above.");
    }
    status("Ready · Files stay on this device");
    actions();
    if (j->op == IMPORT || j->op == REMOVE || app.refresh_again)
        refresh_vault();
    g_free(summary);
}
static void start(Job *j) {
    if (app.busy) {
        job_free(j);
        return;
    }
    const char *messages[] = {"Encrypting and importing files…",
                              "Decrypting and exporting file…",
                              "Verifying and removing file…",
                              "Encrypting file…",
                              "Decrypting file…",
                              "Calculating checksum…"};
    app.busy = TRUE;
    gtk_widget_hide(app.info);
    status(messages[j->op]);
    gtk_widget_show(app.spinner);
    gtk_spinner_start(GTK_SPINNER(app.spinner));
    actions();
    GTask *task = g_task_new(NULL, NULL, finished, NULL);
    g_task_set_task_data(task, j, job_free);
    g_task_run_in_thread(task, work);
    g_object_unref(task);
}
static void import_paths(GPtrArray *paths) {
    if (app.busy || paths->len == 0) {
        g_ptr_array_unref(paths);
        return;
    }
    char *password = password_prompt("Protect your files", TRUE);
    if (!password) {
        g_ptr_array_unref(paths);
        return;
    }
    Job *j = job_new(IMPORT);
    g_ptr_array_unref(j->paths);
    j->paths = paths;
    j->password = password;
    start(j);
}
static void on_add(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    if (app.busy)
        return;
    GtkWidget *d = gtk_file_chooser_dialog_new(
        "Add files to your vault", GTK_WINDOW(app.window), GTK_FILE_CHOOSER_ACTION_OPEN, "Cancel",
        GTK_RESPONSE_CANCEL, "Add files", GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(d), 880, 580);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(d), TRUE);
    GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        GSList *files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(d));
        for (GSList *p = files; p; p = p->next)
            g_ptr_array_add(paths, p->data);
        g_slist_free(files);
    }
    gtk_widget_destroy(d);
    import_paths(paths);
}
static void on_export(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    if (app.busy)
        return;
    gboolean modern;
    char *name = selected(&modern);
    if (!name)
        return;
    if (!modern && !legacy_consent()) {
        g_free(name);
        return;
    }
    char *suggested = g_strndup(name, strlen(name) - 4),
         *output = choose("Export to a new output file", GTK_FILE_CHOOSER_ACTION_SAVE, suggested);
    g_free(suggested);
    if (!output) {
        g_free(name);
        return;
    }
    char *password = password_prompt("Export file", FALSE);
    if (!password) {
        g_free(name);
        g_free(output);
        return;
    }
    Job *j = job_new(EXPORT);
    g_ptr_array_add(j->paths, name);
    j->password = password;
    j->output = output;
    j->legacy = !modern;
    start(j);
}
static void on_remove(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    if (app.busy)
        return;
    gboolean modern;
    char *name = selected(&modern);
    if (!name)
        return;
    if (!modern && !legacy_consent()) {
        g_free(name);
        return;
    }
    char *display = g_filename_display_name(name);
    GtkWidget *d =
        gtk_message_dialog_new(GTK_WINDOW(app.window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
                               GTK_BUTTONS_NONE, "Remove this encrypted file?");
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(d),
        "%s\n\nThis permanently removes the vault copy. Your original file is unaffected. The "
        "file's password is required.",
        display);
    gtk_dialog_add_buttons(GTK_DIALOG(d), "Cancel", GTK_RESPONSE_CANCEL, "Remove file",
                           GTK_RESPONSE_ACCEPT, NULL);
    cls(gtk_dialog_get_widget_for_response(GTK_DIALOG(d), GTK_RESPONSE_ACCEPT), "danger");
    int response = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    g_free(display);
    if (response != GTK_RESPONSE_ACCEPT) {
        g_free(name);
        return;
    }
    char *password = password_prompt("Authorize removal", FALSE);
    if (!password) {
        g_free(name);
        return;
    }
    Job *j = job_new(REMOVE);
    g_ptr_array_add(j->paths, name);
    j->password = password;
    j->legacy = !modern;
    start(j);
}
static void on_manual(GtkWidget *widget, gpointer data) {
    (void)widget;
    if (app.busy)
        return;
    gboolean encrypting = GPOINTER_TO_INT(data);
    char *input = choose(encrypting ? "Choose a file to encrypt" : "Choose a file to decrypt",
                         GTK_FILE_CHOOSER_ACTION_OPEN, NULL);
    if (!input)
        return;
    gboolean legacy = !encrypting && !has_modern_magic(input);
    if (legacy && !legacy_consent()) {
        g_free(input);
        return;
    }
    char *base = g_path_get_basename(input),
         *suggested =
             encrypting ? g_strconcat(base, ".enc", NULL)
                        : (g_str_has_suffix(base, ".enc") ? g_strndup(base, strlen(base) - 4)
                                                          : g_strconcat(base, ".decrypted", NULL));
    char *output = choose("Choose a new output file", GTK_FILE_CHOOSER_ACTION_SAVE, suggested);
    g_free(base);
    g_free(suggested);
    if (!output) {
        g_free(input);
        return;
    }
    char *password = password_prompt(encrypting ? "Encrypt file" : "Decrypt file", encrypting);
    if (!password) {
        g_free(input);
        g_free(output);
        return;
    }
    Job *j = job_new(encrypting ? ENCRYPT : DECRYPT);
    g_ptr_array_add(j->paths, input);
    j->output = output;
    j->password = password;
    j->legacy = legacy;
    start(j);
}
static void on_hash(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    if (app.busy)
        return;
    char *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(app.file));
    if (!path) {
        notice(GTK_MESSAGE_WARNING, "Choose a file to calculate or verify its checksum.");
        return;
    }
    const char *algorithm = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app.algorithm));
    char *expected = g_strdup(gtk_entry_get_text(GTK_ENTRY(app.expected)));
    g_strstrip(expected);
    if (*expected) {
        gboolean valid = strlen(expected) == (!strcmp(algorithm, "sha256") ? 64u : 128u);
        for (const char *c = expected; *c; c++)
            if (!g_ascii_isxdigit(*c))
                valid = FALSE;
        if (!valid) {
            notice(GTK_MESSAGE_WARNING, "Enter a complete hexadecimal checksum for this algorithm, "
                                        "or leave it empty to calculate only.");
            g_free(path);
            g_free(expected);
            return;
        }
    } else
        g_clear_pointer(&expected, g_free);
    Job *j = job_new(HASH);
    g_ptr_array_add(j->paths, path);
    j->algorithm = g_strdup(algorithm);
    j->expected = expected;
    g_clear_pointer(&app.digest_text, g_free);
    gtk_label_set_text(GTK_LABEL(app.digest), "Calculating…");
    gtk_label_set_text(GTK_LABEL(app.hash_status), "Reading the file in the background.");
    gtk_widget_set_sensitive(app.copy, FALSE);
    start(j);
}
static void copy_digest(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    if (app.digest_text) {
        gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), app.digest_text, -1);
        status("Checksum copied to clipboard");
    }
}
static void checksum_input_changed(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    g_clear_pointer(&app.digest_text, g_free);
    gtk_label_set_text(GTK_LABEL(app.digest), "Your checksum will appear here.");
    gtk_label_set_text(GTK_LABEL(app.hash_status),
                       "Calculate again after changing the file or comparison settings.");
    gtk_widget_set_sensitive(app.copy, FALSE);
}

static void item_free(gpointer data) {
    Item *i = data;
    g_free(i->name);
    g_free(i->display);
    g_free(i->format);
    g_free(i->size);
    g_free(i->date);
    g_free(i);
}
static void snapshot_free(gpointer data) {
    Snapshot *s = data;
    g_ptr_array_unref(s->items);
    g_free(s->error);
    g_free(s);
}
static void scan_work(GTask *task, gpointer source, gpointer data, GCancellable *cancel) {
    (void)source;
    (void)data;
    (void)cancel;
    Snapshot *s = g_new0(Snapshot, 1);
    s->items = g_ptr_array_new_with_free_func(item_free);
    if (!ensure_vault_directory()) {
        s->error = g_utf8_make_valid(vault_last_error(), -1);
        goto done;
    }
    GFile *directory = g_file_new_for_path(VAULT_DIR);
    GError *error = NULL;
    GFileEnumerator *enumerator = g_file_enumerate_children(
        directory,
        "standard::name,standard::type,standard::is-symlink,standard::size,time::modified",
        G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
    g_object_unref(directory);
    if (!enumerator) {
        s->error = g_strdup(error->message);
        g_clear_error(&error);
        goto done;
    }
    GFileInfo *info;
    while ((info = g_file_enumerator_next_file(enumerator, NULL, &error))) {
        const char *name = g_file_info_get_name(info);
        if (g_file_info_get_file_type(info) == G_FILE_TYPE_REGULAR &&
            !g_file_info_get_is_symlink(info) && g_str_has_suffix(name, ".enc") &&
            strlen(name) > 4) {
            Item *i = g_new0(Item, 1);
            i->name = g_strdup(name);
            i->display = g_filename_display_name(name);
            i->bytes = (guint64)g_file_info_get_size(info);
            i->mtime =
                (gint64)g_file_info_get_attribute_uint64(info, G_FILE_ATTRIBUTE_TIME_MODIFIED);
            i->size = g_format_size(i->bytes);
            GDateTime *when = g_date_time_new_from_unix_local(i->mtime);
            i->date = when ? g_date_time_format(when, "%d %b %Y · %H:%M") : g_strdup("Unknown");
            if (when)
                g_date_time_unref(when);
            char *path = g_build_filename(VAULT_DIR, name, NULL);
            i->modern = has_modern_magic(path);
            g_free(path);
            i->format = g_strdup(i->modern ? "AES-256-GCM" : "Legacy / unknown");
            if (!i->modern)
                s->legacy++;
            s->bytes += i->bytes;
            g_ptr_array_add(s->items, i);
        }
        g_object_unref(info);
    }
    if (error) {
        s->error = g_strdup(error->message);
        g_clear_error(&error);
    }
    g_object_unref(enumerator);
done:
    g_task_return_pointer(task, s, snapshot_free);
}
static gboolean visible(GtkTreeModel *model, GtkTreeIter *iter, gpointer data) {
    (void)data;
    if (!app.query || !*app.query)
        return TRUE;
    char *name = NULL;
    gtk_tree_model_get(model, iter, DISPLAY, &name, -1);
    char *folded = g_utf8_casefold(name, -1);
    gboolean match = strstr(folded, app.query) != NULL;
    g_free(folded);
    g_free(name);
    return match;
}
static void update_count(void) {
    int shown = gtk_tree_model_iter_n_children(app.sorted, NULL),
        total = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(app.store), NULL);
    char *value = g_strdup_printf("%d of %d file%s", shown, total, total == 1 ? "" : "s");
    gtk_label_set_text(GTK_LABEL(app.count_label), value);
    g_free(value);
    gtk_stack_set_visible_child_name(GTK_STACK(app.vault_pages),
                                     total == 0 ? "empty" : (shown == 0 ? "no-results" : "files"));
}
static void scanned(GObject *source, GAsyncResult *result, gpointer data) {
    (void)source;
    (void)data;
    Snapshot *s = g_task_propagate_pointer(G_TASK(result), NULL);
    gboolean modern;
    char *previous = selected(&modern);
    gtk_list_store_clear(app.store);
    for (guint k = 0; k < s->items->len; k++) {
        Item *i = g_ptr_array_index(s->items, k);
        GtkTreeIter iter;
        gtk_list_store_insert_with_values(app.store, &iter, -1, NAME, i->name, DISPLAY, i->display,
                                          FORMAT, i->format, SIZE, i->size, MODIFIED, i->date,
                                          BYTES, i->bytes, MTIME, i->mtime, ICON,
                                          "text-x-generic-symbolic", MODERN, i->modern, -1);
    }
    if (previous) {
        GtkTreeIter iter;
        gboolean valid = gtk_tree_model_get_iter_first(app.sorted, &iter);
        while (valid) {
            char *name = NULL;
            gtk_tree_model_get(app.sorted, &iter, NAME, &name, -1);
            gboolean match = !strcmp(previous, name);
            g_free(name);
            if (match) {
                gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(app.tree)),
                                               &iter);
                break;
            }
            valid = gtk_tree_model_iter_next(app.sorted, &iter);
        }
    }
    g_free(previous);
    char *count = g_strdup_printf("%u", s->items->len), *space = g_format_size(s->bytes);
    char *protection =
        s->legacy ? g_strdup_printf("%u to review", s->legacy) : g_strdup("AES-256-GCM");
    gtk_label_set_text(GTK_LABEL(app.count), count);
    gtk_label_set_text(GTK_LABEL(app.storage), space);
    gtk_label_set_text(GTK_LABEL(app.protection), protection);
    g_free(count);
    g_free(space);
    g_free(protection);
    if (s->error)
        notice(GTK_MESSAGE_ERROR, s->error);
    snapshot_free(s);
    app.scanning = FALSE;
    update_count();
    actions();
    if (app.refresh_again && !app.busy) {
        app.refresh_again = FALSE;
        refresh_vault();
    }
}
static void refresh_vault(void) {
    if (app.scanning || app.busy) {
        app.refresh_again = TRUE;
        return;
    }
    app.scanning = TRUE;
    app.refresh_again = FALSE;
    actions();
    GTask *task = g_task_new(NULL, NULL, scanned, NULL);
    g_task_run_in_thread(task, scan_work);
    g_object_unref(task);
}
static void on_refresh(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    refresh_vault();
}
static gboolean delayed_refresh(gpointer data) {
    (void)data;
    app.refresh_source = 0;
    refresh_vault();
    return G_SOURCE_REMOVE;
}
static void changed(GFileMonitor *monitor, GFile *file, GFile *other, GFileMonitorEvent event,
                    gpointer data) {
    (void)monitor;
    (void)file;
    (void)other;
    (void)event;
    (void)data;
    if (!app.refresh_source)
        app.refresh_source = g_timeout_add(250, delayed_refresh, NULL);
}
static void search_changed(GtkEditable *entry, gpointer data) {
    (void)data;
    g_free(app.query);
    app.query = g_utf8_casefold(gtk_entry_get_text(GTK_ENTRY(entry)), -1);
    gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(app.filter));
    update_count();
}
static void dropped(GtkWidget *widget, GdkDragContext *context, gint x, gint y,
                    GtkSelectionData *selection, guint info, guint time, gpointer data) {
    (void)widget;
    (void)x;
    (void)y;
    (void)info;
    (void)data;
    GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
    char **uris = gtk_selection_data_get_uris(selection);
    if (uris && !app.busy)
        for (char **uri = uris; *uri; uri++) {
            char *path = g_filename_from_uri(*uri, NULL, NULL);
            if (path)
                g_ptr_array_add(paths, path);
        }
    gboolean accepted = paths->len > 0;
    gtk_drag_finish(context, accepted, FALSE, time);
    g_strfreev(uris);
    if (accepted)
        import_paths(paths);
    else
        g_ptr_array_unref(paths);
}
static void navigate(GtkToggleButton *toggle, gpointer data) {
    if (gtk_toggle_button_get_active(toggle))
        gtk_stack_set_visible_child_name(GTK_STACK(app.pages), data);
}
static gboolean key_pressed(GtkWidget *widget, GdkEventKey *event, gpointer data) {
    (void)widget;
    (void)data;
    if ((event->state & GDK_CONTROL_MASK) &&
        (event->keyval == GDK_KEY_f || event->keyval == GDK_KEY_F)) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app.nav[0]), TRUE);
        gtk_widget_grab_focus(app.search);
        return TRUE;
    }
    if ((event->state & GDK_CONTROL_MASK) &&
        (event->keyval == GDK_KEY_o || event->keyval == GDK_KEY_O)) {
        on_add(NULL, NULL);
        return TRUE;
    }
    if (event->keyval == GDK_KEY_F5) {
        refresh_vault();
        return TRUE;
    }
    return FALSE;
}
static gboolean closing(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget;
    (void)event;
    (void)data;
    if (app.busy) {
        notice(GTK_MESSAGE_INFO,
               "A file operation is still running. Wait for it to finish before closing.");
        return TRUE;
    }
    return FALSE;
}
static GtkWidget *heading(const char *kicker, const char *title, const char *description) {
    GtkWidget *b = box(GTK_ORIENTATION_VERTICAL, 7);
    pack(b, text(kicker, "kicker"), FALSE);
    pack(b, text(title, "title"), FALSE);
    GtkWidget *sub = text(description, "subtitle");
    gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
    pack(b, sub, FALSE);
    return b;
}
static GtkWidget *stat_card(const char *caption, GtkWidget **value, const char *initial,
                            const char *icon) {
    GtkWidget *card = box(GTK_ORIENTATION_HORIZONTAL, 16),
              *labels = box(GTK_ORIENTATION_VERTICAL, 8);
    cls(card, "card");
    pack(labels, text(caption, "muted"), FALSE);
    *value = text(initial, "value");
    pack(labels, *value, FALSE);
    pack(card, labels, TRUE);
    GtkWidget *image = gtk_image_new_from_icon_name(icon, GTK_ICON_SIZE_LARGE_TOOLBAR);
    cls(image, "accent");
    pack(card, image, FALSE);
    return card;
}
static GtkWidget *empty_panel(const char *icon, const char *title, const char *description,
                              gboolean add) {
    GtkWidget *b = box(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_halign(b, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(b, GTK_ALIGN_CENTER);
    GtkWidget *image = gtk_image_new_from_icon_name(icon, GTK_ICON_SIZE_DIALOG);
    cls(image, "accent");
    pack(b, image, FALSE);
    GtkWidget *title_label = text(title, "empty-title");
    gtk_label_set_xalign(GTK_LABEL(title_label), .5f);
    pack(b, title_label, FALSE);
    GtkWidget *sub = text(description, "subtitle");
    gtk_label_set_xalign(GTK_LABEL(sub), .5f);
    gtk_label_set_justify(GTK_LABEL(sub), GTK_JUSTIFY_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
    pack(b, sub, FALSE);
    if (add) {
        GtkWidget *w = button("Add your first files", "list-add-symbolic", "primary",
                              G_CALLBACK(on_add), NULL);
        gtk_widget_set_halign(w, GTK_ALIGN_CENTER);
        pack(b, w, FALSE);
    }
    return b;
}
static GtkWidget *vault_page(void) {
    GtkWidget *page = box(GTK_ORIENTATION_VERTICAL, 22), *top = box(GTK_ORIENTATION_HORIZONTAL, 18);
    pack(top,
         heading("YOUR WORKSPACE", "Personal vault",
                 "A private home for your sensitive files. Encrypted locally, always."),
         TRUE);
    app.add = button("Add files", "list-add-symbolic", "primary", G_CALLBACK(on_add), NULL);
    gtk_widget_set_valign(app.add, GTK_ALIGN_CENTER);
    gtk_widget_set_tooltip_text(app.add, "Import multiple files · Ctrl+O");
    pack(top, app.add, FALSE);
    pack(page, top, FALSE);
    GtkWidget *stats = box(GTK_ORIENTATION_HORIZONTAL, 14);
    gtk_box_set_homogeneous(GTK_BOX(stats), TRUE);
    pack(stats, stat_card("FILES IN VAULT", &app.count, "0", "folder-symbolic"), TRUE);
    pack(stats, stat_card("ENCRYPTED STORAGE", &app.storage, "0 bytes", "drive-harddisk-symbolic"),
         TRUE);
    pack(stats,
         stat_card("FORMAT STATUS", &app.protection, "AES-256-GCM", "security-high-symbolic"),
         TRUE);
    pack(page, stats, FALSE);
    GtkWidget *toolbar = box(GTK_ORIENTATION_HORIZONTAL, 12);
    pack(toolbar, text("Your files", "section"), FALSE);
    app.search = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.search), "Search your vault…");
    pack(toolbar, app.search, TRUE);
    g_signal_connect(app.search, "search-changed", G_CALLBACK(search_changed), NULL);
    app.refresh = button("Refresh", "view-refresh-symbolic", NULL, G_CALLBACK(on_refresh), NULL);
    gtk_widget_set_tooltip_text(app.refresh, "Refresh vault · F5");
    pack(toolbar, app.refresh, FALSE);
    pack(page, toolbar, FALSE);
    app.store = gtk_list_store_new(NCOLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT64, G_TYPE_INT64,
                                   G_TYPE_STRING, G_TYPE_BOOLEAN);
    app.filter = gtk_tree_model_filter_new(GTK_TREE_MODEL(app.store), NULL);
    gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(app.filter), visible, NULL, NULL);
    app.sorted = gtk_tree_model_sort_new_with_model(app.filter);
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(app.sorted), DISPLAY,
                                         GTK_SORT_ASCENDING);
    app.tree = gtk_tree_view_new_with_model(app.sorted);
    gtk_tree_view_set_search_column(GTK_TREE_VIEW(app.tree), DISPLAY);
    GtkCellRenderer *icon = gtk_cell_renderer_pixbuf_new(), *name = gtk_cell_renderer_text_new();
    g_object_set(icon, "xpad", 14, NULL);
    g_object_set(name, "ypad", 17, "ellipsize", PANGO_ELLIPSIZE_MIDDLE, NULL);
    GtkTreeViewColumn *column = gtk_tree_view_column_new();
    gtk_tree_view_column_set_title(column, "FILE NAME");
    gtk_tree_view_column_pack_start(column, icon, FALSE);
    gtk_tree_view_column_add_attribute(column, icon, "icon-name", ICON);
    gtk_tree_view_column_pack_start(column, name, TRUE);
    gtk_tree_view_column_add_attribute(column, name, "text", DISPLAY);
    gtk_tree_view_column_set_expand(column, TRUE);
    gtk_tree_view_column_set_min_width(column, 200);
    gtk_tree_view_column_set_sort_column_id(column, DISPLAY);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app.tree), column);
    const char *titles[] = {"PROTECTION", "SIZE", "MODIFIED"};
    int fields[] = {FORMAT, SIZE, MODIFIED}, sorts[] = {FORMAT, BYTES, MTIME};
    for (unsigned i = 0; i < G_N_ELEMENTS(titles); i++) {
        GtkCellRenderer *cell = gtk_cell_renderer_text_new();
        g_object_set(cell, "xpad", 14, "ypad", 17, NULL);
        column = gtk_tree_view_column_new_with_attributes(titles[i], cell, "text", fields[i], NULL);
        gtk_tree_view_column_set_sort_column_id(column, sorts[i]);
        gtk_tree_view_append_column(GTK_TREE_VIEW(app.tree), column);
    }
    g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(app.tree)), "changed",
                     G_CALLBACK(selection_changed), NULL);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), app.tree);
    app.vault_pages = gtk_stack_new();
    cls(app.vault_pages, "table-frame");
    gtk_stack_add_named(GTK_STACK(app.vault_pages), scroll, "files");
    gtk_stack_add_named(
        GTK_STACK(app.vault_pages),
        empty_panel(
            "folder-symbolic", "Your private space is ready",
            "Add files or drop them here to get started.\nYour original files stay where they are.",
            TRUE),
        "empty");
    gtk_stack_add_named(GTK_STACK(app.vault_pages),
                        empty_panel("system-search-symbolic", "No matching files",
                                    "Try another filename or clear your search.", FALSE),
                        "no-results");
    pack(page, app.vault_pages, TRUE);
    GtkTargetEntry targets[] = {{"text/uri-list", 0, 0}};
    gtk_drag_dest_set(app.vault_pages, GTK_DEST_DEFAULT_ALL, targets, 1, GDK_ACTION_COPY);
    g_signal_connect(app.vault_pages, "drag-data-received", G_CALLBACK(dropped), NULL);
    GtkWidget *footer = box(GTK_ORIENTATION_HORIZONTAL, 10),
              *selection = box(GTK_ORIENTATION_VERTICAL, 5);
    app.count_label = text("0 files", "muted");
    app.selected_label = text("Select a file to export or remove", "muted");
    gtk_label_set_ellipsize(GTK_LABEL(app.selected_label), PANGO_ELLIPSIZE_MIDDLE);
    pack(selection, app.count_label, FALSE);
    pack(selection, app.selected_label, FALSE);
    pack(footer, selection, TRUE);
    app.export = button("Export file", "document-save-symbolic", NULL, G_CALLBACK(on_export), NULL);
    app.remove = button("Remove", "user-trash-symbolic", "danger", G_CALLBACK(on_remove), NULL);
    pack(footer, app.export, FALSE);
    pack(footer, app.remove, FALSE);
    pack(page, footer, FALSE);
    return page;
}
static GtkWidget *tools_page(void) {
    GtkWidget *page = box(GTK_ORIENTATION_VERTICAL, 22);
    pack(page,
         heading("SECURITY TOOLKIT", "Integrity & encryption",
                 "Verify a download or protect a file outside your vault."),
         FALSE);
    GtkWidget *card = box(GTK_ORIENTATION_VERTICAL, 14);
    cls(card, "card");
    pack(card, text("Check a file's integrity", "section"), FALSE);
    GtkWidget *sub = text(
        "Compare a SHA-256 or SHA-512 checksum with one supplied by a trusted source.", "subtitle");
    gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
    pack(card, sub, FALSE);
    GtkWidget *row = box(GTK_ORIENTATION_HORIZONTAL, 10);
    app.file = gtk_file_chooser_button_new("Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN);
    pack(row, app.file, TRUE);
    app.algorithm = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app.algorithm), "sha256", "SHA-256");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app.algorithm), "sha512", "SHA-512");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app.algorithm), 0);
    pack(row, app.algorithm, FALSE);
    pack(card, row, FALSE);
    app.expected = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.expected), "Expected checksum (optional)");
    pack(card, app.expected, FALSE);
    row = box(GTK_ORIENTATION_HORIZONTAL, 10);
    app.hash = button("Calculate & verify", "object-select-symbolic", "primary",
                      G_CALLBACK(on_hash), NULL);
    app.copy = button("Copy checksum", "edit-copy-symbolic", NULL, G_CALLBACK(copy_digest), NULL);
    gtk_widget_set_sensitive(app.copy, FALSE);
    pack(row, app.hash, FALSE);
    pack(row, app.copy, FALSE);
    pack(card, row, FALSE);
    app.digest = text("Your checksum will appear here.", "digest");
    gtk_label_set_selectable(GTK_LABEL(app.digest), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(app.digest), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(app.digest), PANGO_WRAP_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(app.digest), 80);
    pack(card, app.digest, FALSE);
    app.hash_status = text("Files are processed locally in the background.", "muted");
    gtk_label_set_line_wrap(GTK_LABEL(app.hash_status), TRUE);
    pack(card, app.hash_status, FALSE);
    pack(page, card, FALSE);
    g_signal_connect(app.file, "file-set", G_CALLBACK(checksum_input_changed), NULL);
    g_signal_connect(app.algorithm, "changed", G_CALLBACK(checksum_input_changed), NULL);
    g_signal_connect(app.expected, "changed", G_CALLBACK(checksum_input_changed), NULL);
    card = box(GTK_ORIENTATION_VERTICAL, 14);
    cls(card, "card");
    pack(card, text("Protect files anywhere", "section"), FALSE);
    sub = text("Create an encrypted copy in any folder, or decrypt an existing file. Choose a new "
               "destination for every output.",
               "subtitle");
    gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
    pack(card, sub, FALSE);
    row = box(GTK_ORIENTATION_HORIZONTAL, 10);
    app.encrypt = button("Encrypt a file", "changes-prevent-symbolic", NULL, G_CALLBACK(on_manual),
                         GINT_TO_POINTER(TRUE));
    app.decrypt = button("Decrypt a file", "changes-allow-symbolic", NULL, G_CALLBACK(on_manual),
                         GINT_TO_POINTER(FALSE));
    pack(row, app.encrypt, FALSE);
    pack(row, app.decrypt, FALSE);
    pack(card, row, FALSE);
    pack(page, card, FALSE);
    sub = text("Older CBC files require explicit consent. Export and re-import them to upgrade to "
               "authenticated encryption.",
               "muted");
    gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
    pack(page, sub, FALSE);
    return page;
}
static GtkWidget *activity_page(void) {
    GtkWidget *page = box(GTK_ORIENTATION_VERTICAL, 22);
    pack(page,
         heading("THIS SESSION", "Recent activity",
                 "A local record of your latest operations. Cleared when you close the app."),
         FALSE);
    GtkWidget *card = box(GTK_ORIENTATION_VERTICAL, 8);
    cls(card, "card");
    app.activity_empty = text("No operations yet. Your activity will appear here.", "subtitle");
    pack(card, app.activity_empty, FALSE);
    app.activity = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app.activity), GTK_SELECTION_NONE);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), app.activity);
    pack(card, scroll, TRUE);
    pack(page, card, TRUE);
    return page;
}
static void help(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;
    GtkWidget *d =
        gtk_message_dialog_new(GTK_WINDOW(app.window), GTK_DIALOG_MODAL, GTK_MESSAGE_INFO,
                               GTK_BUTTONS_CLOSE, "Secure File Manager");
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(d),
        "C · GTK3 · OpenSSL\n\nCtrl+O  Add files\nCtrl+F  Search vault\nF5  Refresh files\n\nNew "
        "files use AES-256-GCM and PBKDF2-SHA256.\nThe displayed format is detected, not a "
        "password-verified integrity check.\nLegacy CBC files cannot guarantee authenticated "
        "integrity.\nFilenames and sizes remain visible on disk.\nRemoval does not guarantee "
        "secure erasure.");
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}
int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app.window), "Secure File Manager");
    gtk_window_set_default_size(GTK_WINDOW(app.window), 1200, 820);
    gtk_window_set_icon_name(GTK_WINDOW(app.window), "security-high");
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Secure File Manager");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "Your files. Your control.");
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header),
                            button("Help", "help-about-symbolic", NULL, G_CALLBACK(help), NULL));
    gtk_window_set_titlebar(GTK_WINDOW(app.window), header);
    GtkWidget *layout = box(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_add(GTK_CONTAINER(app.window), layout);
    GtkWidget *sidebar = box(GTK_ORIENTATION_VERTICAL, 8);
    cls(sidebar, "app-sidebar");
    gtk_widget_set_size_request(sidebar, 205, -1);
    GtkWidget *brand = box(GTK_ORIENTATION_HORIZONTAL, 10);
    pack(brand, gtk_image_new_from_icon_name("security-high-symbolic", GTK_ICON_SIZE_LARGE_TOOLBAR),
         FALSE);
    pack(brand, text("SecureFiles", "brand"), FALSE);
    pack(sidebar, brand, FALSE);
    GtkWidget *caption = text("PERSONAL FILE VAULT", "caption");
    gtk_widget_set_margin_bottom(caption, 28);
    pack(sidebar, caption, FALSE);
    const char *names[] = {"vault", "tools", "activity"},
               *titles[] = {"Personal vault", "Integrity & tools", "Recent activity"},
               *icons[] = {"folder-symbolic", "security-high-symbolic",
                           "document-open-recent-symbolic"};
    GSList *group = NULL;
    for (unsigned i = 0; i < G_N_ELEMENTS(names); i++) {
        app.nav[i] = gtk_radio_button_new(group);
        group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(app.nav[i]));
        gtk_toggle_button_set_mode(GTK_TOGGLE_BUTTON(app.nav[i]), FALSE);
        cls(app.nav[i], "nav");
        GtkWidget *inner = box(GTK_ORIENTATION_HORIZONTAL, 12);
        pack(inner, gtk_image_new_from_icon_name(icons[i], GTK_ICON_SIZE_BUTTON), FALSE);
        pack(inner, text(titles[i], NULL), FALSE);
        gtk_container_add(GTK_CONTAINER(app.nav[i]), inner);
        pack(sidebar, app.nav[i], FALSE);
    }
    pack(sidebar, box(GTK_ORIENTATION_VERTICAL, 0), TRUE);
    pack(sidebar, gtk_image_new_from_icon_name("computer-symbolic", GTK_ICON_SIZE_LARGE_TOOLBAR),
         FALSE);
    pack(sidebar, text("LOCAL BY DESIGN", "caption"), FALSE);
    GtkWidget *local =
        text("Files stay on this device.\nNo account. No cloud upload.", "sidebar-note");
    gtk_label_set_line_wrap(GTK_LABEL(local), TRUE);
    pack(sidebar, local, FALSE);
    pack(layout, sidebar, FALSE);
    GtkWidget *main = box(GTK_ORIENTATION_VERTICAL, 16);
    gtk_container_set_border_width(GTK_CONTAINER(main), 28);
    pack(layout, main, TRUE);
    app.info = gtk_info_bar_new_with_buttons("Dismiss", GTK_RESPONSE_CLOSE, NULL);
    app.info_label = text("", NULL);
    gtk_label_set_line_wrap(GTK_LABEL(app.info_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(app.info_label), 90);
    gtk_container_add(GTK_CONTAINER(gtk_info_bar_get_content_area(GTK_INFO_BAR(app.info))),
                      app.info_label);
    g_signal_connect(app.info, "response", G_CALLBACK(dismiss), NULL);
    pack(main, app.info, FALSE);
    app.pages = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app.pages), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(GTK_STACK(app.pages), 150);
    gtk_stack_add_named(GTK_STACK(app.pages), vault_page(), "vault");
    gtk_stack_add_named(GTK_STACK(app.pages), tools_page(), "tools");
    gtk_stack_add_named(GTK_STACK(app.pages), activity_page(), "activity");
    pack(main, app.pages, TRUE);
    for (unsigned i = 0; i < G_N_ELEMENTS(names); i++)
        g_signal_connect(app.nav[i], "toggled", G_CALLBACK(navigate), (gpointer)names[i]);
    GtkWidget *footer = box(GTK_ORIENTATION_HORIZONTAL, 10);
    cls(footer, "footer");
    app.spinner = gtk_spinner_new();
    pack(footer, app.spinner, FALSE);
    app.status = text("Ready · Files stay on this device", "muted");
    pack(footer, app.status, TRUE);
    pack(footer, text("C / GTK3 / OpenSSL", "muted"), FALSE);
    pack(main, footer, FALSE);
    g_signal_connect(app.window, "delete-event", G_CALLBACK(closing), NULL);
    g_signal_connect(app.window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(app.window, "key-press-event", G_CALLBACK(key_pressed), NULL);
    gtk_widget_show_all(app.window);
    gtk_widget_hide(app.info);
    gtk_widget_hide(app.spinner);
    gtk_stack_set_visible_child_name(GTK_STACK(app.pages), "vault");
    actions();
    refresh_vault();
    if (ensure_vault_directory()) {
        GFile *directory = g_file_new_for_path(VAULT_DIR);
        app.monitor = g_file_monitor_directory(directory, G_FILE_MONITOR_NONE, NULL, NULL);
        if (app.monitor)
            g_signal_connect(app.monitor, "changed", G_CALLBACK(changed), NULL);
        g_object_unref(directory);
    }
    gtk_main();
    if (app.refresh_source)
        g_source_remove(app.refresh_source);
    g_clear_object(&app.monitor);
    g_clear_object(&app.sorted);
    g_clear_object(&app.filter);
    g_clear_object(&app.store);
    g_free(app.query);
    g_free(app.digest_text);
    return 0;
}
