import sqlite3

import objects
import constants as const
import os

def dropDB():
    os.path.unlink(const.DB_NAME)

def createDB():
    print('Creating database now')
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS objects(oid VARCHAR(64) PRIMARY KEY, obj TEXT NOT NULL)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS block_utxos (
                blockid VARCHAR(64) PRIMARY KEY,
                utxo TEXT NOT NULL,
                FOREIGN KEY (blockid) REFERENCES objects(oid) ON DELETE CASCADE
            )
        """)

        # Preload genesis block
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (const.GENESIS_BLOCK_ID,))
        if res.fetchone() is None:
            gen_id = objects.get_objid(const.GENESIS_BLOCK)
            if gen_id != const.GENESIS_BLOCK_ID:
                raise Exception("Invalid genesis block!")

            gen_str = objects.canonicalize(const.GENESIS_BLOCK).decode('utf-8')

            cur.execute("INSERT INTO objects VALUES(?, ?)", (gen_id, gen_str))
            cur.execute("INSERT INTO block_utxos VALUES(?, ?)", (gen_id, "{}"))

        con.commit()

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()


if __name__ == "__main__":
    createDB()
