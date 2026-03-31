import { initWorker } from './sqlite-worker';
import { up } from './migrations';
import { setDbId } from './db';
let dbId: string;


export async function initSQLite() {
  const promiser = await initWorker();

  const config = await promiser('config-get', {});
  console.log('SQLite version:', config.result.version.libVersion);

  const openResponse = await promiser('open', {
    filename: 'file:app.db?vfs=opfs',
  });

  dbId = openResponse.dbId;
  setDbId(dbId);
  console.log('Database opened:', openResponse.result.filename);

  const result = await up();
  console.log('Migrations applied:', result.result, result.rows);
}

