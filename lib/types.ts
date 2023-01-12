export type DeepWriteable<T> = {
  -readonly [P in keyof T]: DeepWriteable<T[P]>;
};

export type DeepReadonly<T> = {
  +readonly [P in keyof T]: DeepReadonly<T[P]>;
};
