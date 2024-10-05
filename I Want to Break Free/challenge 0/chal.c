#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_NOTES 512
#define MAX_NOTE_LENGTH 128

char *notes[MAX_NOTES] = {0};
bool deleted[MAX_NOTES] = {0};

void get_input(char *out, size_t length) {
    fgets(out, length, stdin);
    out[strcspn(out, "\n")] = 0;
}

void view_secret() {
    char *password_buf = malloc(128);
    strcpy(password_buf, "FakePassword"); // this is not actually the password

    char *entered_password_buf = malloc(128);
    printf("Enter the password to access the secret note: ");

    get_input(entered_password_buf, 128);
    if (strcmp(password_buf, entered_password_buf) == 0) {
        char flag[256];
        FILE *flag_file = fopen("flag.txt", "r");
        size_t flag_len = fread(flag, 1, 255, flag_file);
        fclose(flag_file);
        flag[flag_len] = 0;
        printf("You Win! Flag is %s.\n", flag);
    } else {
        printf("Passwords did not match...\n");
    }
    free(password_buf);
    free(entered_password_buf);
}

uint8_t create_note(const char *contents, size_t length) {
    if (length > MAX_NOTE_LENGTH) {
        return 1; // note is too long to store
    }
    uint32_t note_idx = 0;
    while (notes[note_idx] != 0 && !deleted[note_idx]) {
        note_idx++;
        if (note_idx == MAX_NOTES) {
            return 2; // no room for more notes
        }
    }
    char *new_note = malloc(length);
    memcpy(new_note, contents, length);
    new_note[length - 1] = 0; // make sure note is null-terminated
    notes[note_idx] = new_note;
    deleted[note_idx] = false;
    return 0;
}

void delete_note(uint32_t note) {
    free(notes[note]);
    deleted[note] = true; // much easier than modifying the notes array :)
}

void menu_create_note() {
    char body[MAX_NOTE_LENGTH] = {0};
    int err = 0;
    printf("Enter note contents (up to 128 characters): ");
    get_input(body, MAX_NOTE_LENGTH);
    if (!create_note(body, MAX_NOTE_LENGTH)) {
        printf("Note created successfully.\n");
    }
}

void menu_view_note() {
    uint32_t note_id;
    char note_id_str[4];
    printf("Enter note id: ");
    fgets(note_id_str, 4, stdin);
    note_id = strtoul(note_id_str, NULL, 10);
    if (note_id > MAX_NOTES || notes[note_id] == 0 || deleted[note_id]) {
        printf("Note does not exist.\n");
        return;
    }
    printf("%s\n", notes[note_id]);
}

void menu_list_notes() {
    printf("Your Notes:\n");
    for (int i = 0; notes[i] != 0 && i < MAX_NOTES; i++) {
        if (!deleted[i]) {
            printf("%d", i);
        }
    }
}

void menu_delete_note() {
    uint32_t note_id;
    char note_id_str[4];
    printf("Enter note ID to delete: ");
    fgets(note_id_str, 4, stdin);
    note_id = strtoul(note_id_str, NULL, 10);
    if (note_id > MAX_NOTES || notes[note_id] == 0) {
        printf("Note does not exist.\n");
        return;
    }
    delete_note(note_id);
    printf("Note deleted successfully.\n");
}

void menu_loop() {
    int res;
    uint8_t choice;
    char str_choice[3];
    while (1) {
        printf("Options:\n1: List Notes\n2: "
               "Create Note\n3: View "
               "Note\n4: Delete Note"
               "\n5: View Secret Note\n6: Exit\n> ");

        fgets(str_choice, 3, stdin);
        choice = strtoul(str_choice, NULL, 10);
        switch (choice) {
        case 1:
            menu_list_notes();
            break;
        case 2:
            menu_create_note();
            break;
        case 3:
            menu_view_note();
            break;
        case 4:
            menu_delete_note();
            break;
        case 5:
            view_secret();
            break;
        case 6:
            return;
        }
    }
}

int main() {
    printf("Ultra-Advanced Futuristic notes app\n---------------------\n");
    menu_loop();
    printf("Goodbye...\n");
    return 0;
}
