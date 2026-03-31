let dbId: string | null = null;

export function setDbId(id: string) {
  dbId = id;
}

export function getDbId() {
  if (!dbId) throw new Error("DB not initialized");
  return dbId;
}