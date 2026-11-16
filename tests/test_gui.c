/* Integration harness: run the production GTK main loop and background jobs.
 * No dialog automation or test switches are added to the application itself. */
#define main sfm_gui_main
#include "../gui_gtk.c"
#undef main

static const char TEST_PASSWORD[] = "integration-test-password-2026";
static const char REPORT[] = "Quarterly project report\nConfidential test fixture.\n";
static const char SHA256_ABC[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static const char SHA512_ABC[] = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
static char *report_path, *hash_path, *export_path;
static gint64 deadline, next_action;
static unsigned stage, busy_ticks, assertions;
static gboolean failed, password_probe_completed;

static gboolean require(gboolean condition, const char *message) {
    assertions++;
    if (condition)
        return TRUE;
    g_printerr("GUI integration failed at stage %u: %s\n", stage, message);
    failed = TRUE;
    gtk_main_quit();
    return FALSE;
}
#define REQUIRE(condition, message)                                                                \
    do {                                                                                           \
        if (!require((condition), (message)))                                                      \
            return G_SOURCE_REMOVE;                                                                \
    } while (0)

static gboolean idle(void) {
    return !app.busy && !app.scanning && !app.refresh_source && !app.refresh_again;
}
static int total_files(void) {
    return gtk_tree_model_iter_n_children(GTK_TREE_MODEL(app.store), NULL);
}
static int visible_files(void) { return gtk_tree_model_iter_n_children(app.sorted, NULL); }

static void capture_widget(GtkWidget *widget, const char *name) {
    const char *directory = g_getenv("SFM_SCREENSHOT_DIR");
    if (!directory || !*directory)
        return;
    g_mkdir_with_parents(directory, 0700);
    int width = gtk_widget_get_allocated_width(widget);
    int height = gtk_widget_get_allocated_height(widget);
    char *path = g_build_filename(directory, name, NULL);
    /* Capture this application's window, including native child windows such
     * as GtkTreeView headers. Widget drawing alone omits those on Win32. */
    GdkPixbuf *pixels =
        gdk_pixbuf_get_from_window(gtk_widget_get_window(widget), 0, 0, width, height);
    if (pixels) {
        /* Some layered Win32 windows return a black surface without an error. */
        gboolean visible_pixels = FALSE;
        const guchar *data = gdk_pixbuf_read_pixels(pixels);
        int stride = gdk_pixbuf_get_rowstride(pixels), channels = gdk_pixbuf_get_n_channels(pixels);
        for (int y = 0; y < height && !visible_pixels; y += 8)
            for (int x = 0; x < width; x += 8) {
                const guchar *pixel = data + y * stride + x * channels;
                if (pixel[0] || pixel[1] || pixel[2]) {
                    visible_pixels = TRUE;
                    break;
                }
            }
        if (!visible_pixels)
            g_clear_object(&pixels);
    }
    if (pixels) {
        GError *error = NULL;
        if (!gdk_pixbuf_save(pixels, path, "png", &error, NULL)) {
            g_printerr("Could not save screenshot %s: %s\n", path, error->message);
            g_clear_error(&error);
            failed = TRUE;
        }
        g_object_unref(pixels);
        g_free(path);
        return;
    }
    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
    cairo_t *context = cairo_create(surface);
    cairo_set_source_rgb(context, 1, 1, 1);
    cairo_paint(context);
    gtk_widget_draw(widget, context);
    if (widget == app.window && gtk_widget_get_mapped(app.tree)) {
        /* Win32 native header child windows are omitted by ancestor drawing.
         * Draw the real header widgets at their GTK-assigned positions. */
        GList *columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(app.tree));
        for (GList *column = columns; column; column = column->next) {
            GtkWidget *header = gtk_tree_view_column_get_button(column->data);
            int x, y;
            if (header && gtk_widget_get_mapped(header) &&
                gtk_widget_translate_coordinates(header, widget, 0, 0, &x, &y)) {
                cairo_save(context);
                cairo_translate(context, x, y);
                gtk_widget_draw(header, context);
                cairo_restore(context);
            }
        }
        g_list_free(columns);
    }
    cairo_status_t result = cairo_surface_write_to_png(surface, path);
    if (result != CAIRO_STATUS_SUCCESS) {
        g_printerr("Could not render screenshot %s: %s\n", path, cairo_status_to_string(result));
        failed = TRUE;
    }
    g_free(path);
    cairo_destroy(context);
    cairo_surface_destroy(surface);
}
static void capture(const char *name) { capture_widget(app.window, name); }

static void find_prompt_widgets(GtkWidget *widget, GPtrArray *entries, GtkWidget **generate) {
    if (GTK_IS_ENTRY(widget))
        g_ptr_array_add(entries, widget);
    if (GTK_IS_BUTTON(widget) &&
        g_strcmp0(gtk_button_get_label(GTK_BUTTON(widget)), "Generate") == 0)
        *generate = widget;
    if (GTK_IS_CONTAINER(widget)) {
        GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
        for (GList *child = children; child; child = child->next)
            find_prompt_widgets(GTK_WIDGET(child->data), entries, generate);
        g_list_free(children);
    }
}
static gboolean finish_password_probe(gpointer data) {
    GtkWidget *dialog = data;
    capture_widget(dialog, "gui-password.png");
    gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL);
    return G_SOURCE_REMOVE;
}
static gboolean probe_password(gpointer data) {
    (void)data;
    GtkWidget *dialog = NULL;
    GList *windows = gtk_window_list_toplevels();
    for (GList *window = windows; window; window = window->next)
        if (GTK_IS_DIALOG(window->data) && g_strcmp0(gtk_window_get_title(GTK_WINDOW(window->data)),
                                                     "Integration password test") == 0)
            dialog = window->data;
    g_list_free(windows);
    if (!dialog)
        return G_SOURCE_CONTINUE;
    GPtrArray *entries = g_ptr_array_new();
    GtkWidget *generate = NULL;
    find_prompt_widgets(dialog, entries, &generate);
    gboolean valid = require(entries->len == 2 && generate,
                             "password dialog provides password, confirmation and generation");
    if (valid) {
        GtkWidget *accept =
            gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
        GtkWidget *password = g_ptr_array_index(entries, 0);
        GtkWidget *confirmation = g_ptr_array_index(entries, 1);
        valid &= require(!gtk_widget_get_sensitive(accept), "empty password cannot be accepted");
        gtk_entry_set_text(GTK_ENTRY(password), "short");
        gtk_entry_set_text(GTK_ENTRY(confirmation), "short");
        valid &= require(!gtk_widget_get_sensitive(accept), "short password cannot be accepted");
        gtk_entry_set_text(GTK_ENTRY(password), TEST_PASSWORD);
        gtk_entry_set_text(GTK_ENTRY(confirmation), "different-password");
        valid &= require(!gtk_widget_get_sensitive(accept), "mismatched confirmation is rejected");
        gtk_entry_set_text(GTK_ENTRY(confirmation), TEST_PASSWORD);
        valid &=
            require(gtk_widget_get_sensitive(accept), "matching long password can be accepted");
        gtk_button_clicked(GTK_BUTTON(generate));
        const char *value = gtk_entry_get_text(GTK_ENTRY(password));
        valid &= require(strlen(value) == 32 &&
                             !strcmp(value, gtk_entry_get_text(GTK_ENTRY(confirmation))),
                         "secure generated password fills both entries with 32 characters");
        valid &= require(!gtk_entry_get_visibility(GTK_ENTRY(password)) &&
                             !gtk_entry_get_visibility(GTK_ENTRY(confirmation)),
                         "generated password remains masked");
    }
    password_probe_completed = valid;
    g_ptr_array_unref(entries);
    if (valid)
        /* Let GTK allocate the changed entry/meter before rendering the dialog. */
        g_timeout_add_full(G_PRIORITY_DEFAULT, 100, finish_password_probe, g_object_ref(dialog),
                           g_object_unref);
    else
        gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL);
    return G_SOURCE_REMOVE;
}

static Job *single_job(Operation operation, const char *path, const char *password) {
    Job *job = job_new(operation);
    g_ptr_array_add(job->paths, g_strdup(path));
    job->password = password ? g_strdup(password) : NULL;
    return job;
}

static gboolean step(gpointer data) {
    (void)data;
    if (g_get_monotonic_time() > deadline) {
        require(FALSE, "timed out waiting for a background operation or GTK state");
        return G_SOURCE_REMOVE;
    }
    if (app.busy)
        busy_ticks++;
    if (!idle() || g_get_monotonic_time() < next_action)
        return G_SOURCE_CONTINUE;
    switch (stage) {
    case 0: {
        REQUIRE(total_files() == 0, "new vault must be empty");
        REQUIRE(!strcmp(gtk_stack_get_visible_child_name(GTK_STACK(app.vault_pages)), "empty"),
                "empty vault panel must be visible");
        REQUIRE(!gtk_widget_get_sensitive(app.export), "export requires a selected file");
        REQUIRE(!gtk_widget_get_sensitive(app.remove), "removal requires a selected file");
        gtk_window_resize(GTK_WINDOW(app.window), 1200, 820);
        next_action = g_get_monotonic_time() + 200000;
        stage++;
        break;
    }
    case 1: {
        capture("gui-empty.png");
        g_timeout_add(50, probe_password, NULL);
        char *password = password_prompt("Integration password test", TRUE);
        gboolean canceled = password == NULL;
        if (password) {
            OPENSSL_cleanse(password, strlen(password));
            g_free(password);
        }
        REQUIRE(password_probe_completed, "password-dialog validation checks completed");
        REQUIRE(canceled, "canceling the password dialog starts no operation");
        REQUIRE(g_file_set_contents(report_path, REPORT, -1, NULL), "create report fixture");
        REQUIRE(g_file_set_contents(hash_path, "abc", 3, NULL), "create hash fixture");
        Job *job = single_job(IMPORT, report_path, TEST_PASSWORD);
        g_ptr_array_add(job->paths, g_strdup(hash_path));
        start(job);
        REQUIRE(app.busy, "batch import must start a worker");
        REQUIRE(!gtk_widget_get_sensitive(app.add), "import is disabled while a worker runs");
        stage++;
        break;
    }
    case 2: {
        REQUIRE(total_files() == 2, "batch import must publish two vault entries");
        REQUIRE(!strcmp(gtk_label_get_text(GTK_LABEL(app.count)), "2"), "dashboard count updates");
        REQUIRE(busy_ticks >= 2, "GTK timer must continue during encryption");
        REQUIRE(g_file_test(".vault/Quarterly report.txt.enc", G_FILE_TEST_IS_REGULAR),
                "report encrypted copy exists");
        REQUIRE(g_file_test(".vault/STRASSE.txt.enc", G_FILE_TEST_IS_REGULAR),
                "second encrypted copy exists");
        GtkTreeIter first;
        REQUIRE(gtk_tree_model_get_iter_first(app.sorted, &first),
                "imported files can be selected");
        gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(app.tree)),
                                       &first);
        REQUIRE(gtk_widget_get_sensitive(app.export), "selection enables export");
        gtk_widget_hide(app.info);
        next_action = g_get_monotonic_time() + 200000;
        stage++;
        break;
    }
    case 3:
        capture("gui-vault.png");
        gtk_entry_set_text(GTK_ENTRY(app.search), "stra\303\237e");
        search_changed(GTK_EDITABLE(app.search), NULL);
        REQUIRE(visible_files() == 1, "Unicode casefold query must match STRASSE");
        gtk_entry_set_text(GTK_ENTRY(app.search), "no-such-file-9271");
        search_changed(GTK_EDITABLE(app.search), NULL);
        REQUIRE(visible_files() == 0, "unmatched search must filter all rows");
        REQUIRE(!strcmp(gtk_stack_get_visible_child_name(GTK_STACK(app.vault_pages)), "no-results"),
                "unmatched query must show the no-results panel");
        next_action = g_get_monotonic_time() + 250000;
        stage++;
        break;
    case 4: {
        capture("gui-no-results.png");
        gtk_entry_set_text(GTK_ENTRY(app.search), "");
        search_changed(GTK_EDITABLE(app.search), NULL);
        REQUIRE(visible_files() == 2, "clearing the search restores both rows");
        Job *job = single_job(EXPORT, "Quarterly report.txt.enc", TEST_PASSWORD);
        job->output = g_strdup(export_path);
        start(job);
        stage++;
        break;
    }
    case 5: {
        char *contents = NULL;
        gsize length = 0;
        REQUIRE(g_file_get_contents(export_path, &contents, &length, NULL),
                "export creates output");
        gboolean equal = length == strlen(REPORT) && memcmp(contents, REPORT, length) == 0;
        g_free(contents);
        REQUIRE(equal, "exported bytes must match the original file");
        start(single_job(REMOVE, "Quarterly report.txt.enc", "incorrect-password"));
        stage++;
        break;
    }
    case 6:
        REQUIRE(total_files() == 2, "wrong password must preserve the vault entry");
        REQUIRE(g_file_test(".vault/Quarterly report.txt.enc", G_FILE_TEST_IS_REGULAR),
                "wrong password must preserve the encrypted file");
        REQUIRE(gtk_info_bar_get_message_type(GTK_INFO_BAR(app.info)) == GTK_MESSAGE_ERROR,
                "failed removal must show a visible error");
        start(single_job(REMOVE, "Quarterly report.txt.enc", TEST_PASSWORD));
        stage++;
        break;
    case 7:
        REQUIRE(total_files() == 1, "authorized removal updates the file list");
        REQUIRE(!g_file_test(".vault/Quarterly report.txt.enc", G_FILE_TEST_EXISTS),
                "authorized removal deletes the vault copy");
        REQUIRE(g_file_test(report_path, G_FILE_TEST_IS_REGULAR), "original file remains intact");
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app.nav[1]), TRUE);
        REQUIRE(gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(app.file), hash_path),
                "checksum file can be selected");
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(app.algorithm), "sha256");
        gtk_entry_set_text(GTK_ENTRY(app.expected), SHA256_ABC);
        next_action = g_get_monotonic_time() + 300000;
        stage++;
        break;
    case 8: {
        char *selected_file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(app.file));
        gboolean selected_correctly = selected_file && !strcmp(selected_file, hash_path);
        g_free(selected_file);
        REQUIRE(selected_correctly, "checksum worker reads the selected file");
        on_hash(NULL, NULL);
        REQUIRE(app.busy, "checksum callback starts a background worker");
        REQUIRE(!gtk_widget_get_sensitive(app.expected),
                "comparison settings freeze during hashing");
        stage++;
        break;
    }
    case 9:
        REQUIRE(app.digest_text && !strcmp(app.digest_text, SHA256_ABC),
                "SHA-256 digest is correct");
        REQUIRE(strstr(gtk_label_get_text(GTK_LABEL(app.hash_status)), "Checksums match") != NULL,
                "matching supplied checksum is reported");
        REQUIRE(gtk_widget_get_sensitive(app.copy), "completed digest can be copied");
        next_action = g_get_monotonic_time() + 200000;
        stage++;
        break;
    case 10:
        capture("gui-tools.png");
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(app.algorithm), "sha512");
        REQUIRE(app.digest_text == NULL, "changing algorithm invalidates the previous result");
        REQUIRE(!gtk_widget_get_sensitive(app.copy), "stale digest cannot be copied");
        gtk_entry_set_text(GTK_ENTRY(app.expected), SHA512_ABC);
        on_hash(NULL, NULL);
        stage++;
        break;
    case 11:
        REQUIRE(app.digest_text && !strcmp(app.digest_text, SHA512_ABC),
                "SHA-512 digest is correct");
        REQUIRE(strstr(gtk_label_get_text(GTK_LABEL(app.hash_status)), "Checksums match") != NULL,
                "SHA-512 comparison uses the submitted algorithm and checksum");
        gtk_entry_set_text(GTK_ENTRY(app.expected), "invalid-checksum");
        on_hash(NULL, NULL);
        REQUIRE(!app.busy, "invalid checksum must be rejected before starting a worker");
        REQUIRE(app.digest_text == NULL, "invalid comparison leaves no stale digest");
        REQUIRE(gtk_info_bar_get_message_type(GTK_INFO_BAR(app.info)) == GTK_MESSAGE_WARNING,
                "invalid checksum produces a visible warning");
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app.nav[2]), TRUE);
        gtk_widget_hide(app.info);
        next_action = g_get_monotonic_time() + 250000;
        stage++;
        break;
    case 12:
        REQUIRE(app.activity_count >= 6,
                "session activity records completed and failed operations");
        capture("gui-activity.png");
        g_print("GUI integration passed: %u assertions; password confirmation/generation, "
                "batch import, responsive GTK loop, "
                "Unicode search, export, password-authorized removal, SHA-256/SHA-512 and stale "
                "result handling.\n",
                assertions);
        gtk_widget_destroy(app.window);
        return G_SOURCE_REMOVE;
    default:
        require(FALSE, "invalid integration stage");
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

int main(int argc, char **argv) {
    char *directory = g_get_current_dir();
    report_path = g_build_filename(directory, "Quarterly report.txt", NULL);
    hash_path = g_build_filename(directory, "STRASSE.txt", NULL);
    export_path = g_build_filename(directory, "Exported report.txt", NULL);
    g_free(directory);
    deadline = g_get_monotonic_time() + 45000000;
    g_timeout_add(25, step, NULL);
    int result = sfm_gui_main(argc, argv);
    g_free(report_path);
    g_free(hash_path);
    g_free(export_path);
    return failed || stage != 12 ? 1 : result;
}
