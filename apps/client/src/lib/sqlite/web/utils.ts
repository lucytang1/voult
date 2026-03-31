import { getDbId } from "./db";
import { initWorker } from "./sqlite-worker";
import { ExecOptions } from "./type";

export async function sql<T = any, R = any>(sql: ExecOptions['sql'], bind?: ExecOptions['bind']): Promise<{ rows: T[], result: R }> {
    const dbId = getDbId();
    const promiser = await initWorker();
    const rows: T[] = [];

    const result = await promiser('exec', {
        dbId,
        sql,
        bind,
        rowMode: 'object',
        resultRows: rows,
    })
  return {
    rows: result.result.resultRows as T[],
    result
  };
}