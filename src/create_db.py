import sqlite3

import objects
import constants as const

def main():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        # Build database
        cur.execute(
            """CREATE TABLE IF NOT EXISTS objects (
                id VARCHAR(64) PRIMARY KEY,
                object BLOB NOT NULL
            )"""
        )
        con.commit()

        # TODO - Preload genesis block

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()


if __name__ == "__main__":
    main()
