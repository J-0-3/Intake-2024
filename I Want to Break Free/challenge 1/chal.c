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

void win() {
  char flag[256];
  FILE *flag_file = fopen("flag.txt", "r");
  size_t flag_len = fread(flag, 1, 255, flag_file);
  fclose(flag_file);
  flag[flag_len] = 0;
  printf("You Win! Flag is: %s.\n", flag);
}

void get_input(char *out, size_t length) {
  fgets(out, length, stdin);
  out[strcspn(out, "\n")] = 0;
}

uint8_t create_note(const char *contents) {
  if (strlen(contents) > MAX_NOTE_LENGTH) {
    return 1; // note is too long to store
  }
  uint32_t note_idx = 0;
  while (notes[note_idx] != 0 && !deleted[note_idx]) {
    note_idx++;
    if (note_idx == MAX_NOTES) {
      return 2; // no room for more notes
    }
  }
  char *new_note = malloc(MAX_NOTE_LENGTH);
  strcpy(new_note, contents);
  notes[note_idx] = new_note;
  deleted[note_idx] = false;
  return 0;
}

void delete_note(uint32_t note) {
  free(notes[note]);
  deleted[note] = true; // much easier than modifying the notes array :)
}

// everything below this is mostly irrelevant to the challenge

void menu_create_note() {
  char body[MAX_NOTE_LENGTH] = {0};
  int err = 0;
  printf("Enter note contents (up to 128 characters): ");
  get_input(body, MAX_NOTE_LENGTH);
  if ((err = create_note(body))) {
    switch (err) {
    case 1:
      printf("Note contents exceed maximum allowed length (128 "
             "characters).");
      break;
    case 2:
      printf("Note title exceeds maximum allowed length (32 characters).");
      break;
    case 3:
      printf("No space available for additional notes.");
    }
    return;
  }
  printf("Note created successfully.");
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
  printf("Note deleted successfully.");
}

void menu_loop() {
  int res;
  uint8_t choice;
  char str_choice[3];
  printf("DEBUG: choice is located at %p\n", &choice);
  while (1) {
    printf("Options:\n1: List Notes\n2: "
           "Create Note\n3: View "
           "Note\n4: Delete Note"
           "\n5: Exit\n> ");

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
