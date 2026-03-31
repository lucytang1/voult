import * as sqliteWasm from "@sqlite.org/sqlite-wasm";

let promiser: any;

export async function initWorker() {
    if (promiser) {
        return promiser;
      }
      
    const sqlite3Worker1Promiser = (sqliteWasm as any).sqlite3Worker1Promiser;
    if (typeof sqlite3Worker1Promiser !== "function") {
      throw new Error("sqlite3Worker1Promiser is not available from @sqlite.org/sqlite-wasm");
    }
  
    promiser = await sqlite3Worker1Promiser();
    return promiser;
  }