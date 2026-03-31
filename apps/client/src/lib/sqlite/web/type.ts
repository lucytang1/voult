export type ExecOptions = {
  sql: string | string[];
  bind?: any[] | Record<string, any>;
  rowMode?: "array" | "object" | "stmt";
  resultRows?: any[];
  columnNames?: string[];
  callback?: (row: any) => void;
  countChanges?: boolean;
  multi?: boolean;
  saveSql?: string[];
  returnValue?: "resultRows" | "stmt";
  dbId?: string;
};

export type operation_type = {
  create: "create";
  update: "update";
  delete: "delete";
};
