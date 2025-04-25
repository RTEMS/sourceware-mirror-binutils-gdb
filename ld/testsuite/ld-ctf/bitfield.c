enum foo { FOO_BAR };

struct bitfields {
  int one : 1;
  int two : 2;
  int six : 6;
  int ten :10;
  enum foo bar:1;
} bitfields; 
