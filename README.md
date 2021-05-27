PMStore is a transactional object storage framework for persistent memorry.

PMStore is motivated by the object storage architecture that seperates the functional modules of conventional file systems into "file management" and "storage management".

File system-based storage architecture is inefficient for two reasons:

First, file management can incur significant software overheads in file path resolution, and is not necessary for file system-based softwares, such as SQLite (Relational database) and Tokyo Cabinet (Key-Value store). 

Second, standard file system interfaces does not provide ACID (Atomicity, Consistency, Isolation, Durability) transactional semantics.
 Transactional semantics are commonly used by software, such as lightweight databases and key-value stores.
