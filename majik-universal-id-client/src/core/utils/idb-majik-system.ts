// lib/indexedDB.ts
import { openDB, type IDBPDatabase } from "idb";

export interface MajikIDBSaveData {
  id: string;
  data: Blob;
  savedAt: number;
}

interface MajikAutosaveSchema {
  majikdata: MajikIDBSaveData;
}

let dbPromise: Promise<IDBPDatabase<MajikAutosaveSchema>>;

export function initDB(name: string = "default") {
  if (!dbPromise) {
    const dbName = `MajikAutosaveDB_${name}`;
    dbPromise = openDB(dbName, 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains("majikdata")) {
          db.createObjectStore("majikdata", { keyPath: "id" });
        }
      },
    });
  }
  return dbPromise;
}

export async function idbSaveBlob(
  id: string,
  data: Blob,
  name: string = "default",
) {
  const db = await initDB(name);
  await db.put("majikdata", { id, data, savedAt: Date.now() });
}

export async function idbLoadBlob(
  id: string,
  name: string = "default",
): Promise<MajikIDBSaveData | undefined> {
  try {
    const db = await initDB(name);
    return await db.get("majikdata", id);
  } catch (err) {
    console.error(`Failed to load blob with id "${id}":`, err);
    return undefined;
  }
}

export async function deleteBlob(
  id: string,
  name: string = "default",
): Promise<void> {
  try {
    const db = await initDB(name);
    return db.delete("majikdata", id);
  } catch (err) {
    console.error(`Failed to delete blob with id "${id}":`, err);
    return undefined;
  }
}

export async function clearAllBlobs(name: string = "default"): Promise<void> {
  const db = await initDB(name);
  return db.clear("majikdata");
}
