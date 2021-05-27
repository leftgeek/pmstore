PMStore is a transactional object storage framework for persistent memorry.

PMStore is motivated by the object storage architecture that seperates the functional modules of conventional file systems into "file management" and "storage management".

File system-based storage architecture is inefficient for two reasons:

First, file management can incur significant software overheads in file path resolution, and is not necessary for file system-based softwares, such as SQLite (Relational database) and Tokyo Cabinet (Key-Value store). 

Second, standard file system interfaces does not provide ACID (Atomicity, Consistency, Isolation, Durability) transactional semantics.
However, transactional semantics are commonly used by software, such as lightweight databases and key-value stores.
In this situations, a software need to achieve ACID itself, typically by journaling.
On the other hand, file system itself also emploies techniques such as journaling to guarantee the atomicity and consistency of each file read and write operation.
As a result, file system-based software suffers from "double journaling" overheads that can affect I/O performance significantly.

PMStore removes file management overhead by allowing applications to bypass the file management component and directly communicate with storage management component.

PMStore further removes double journaling overheads by providing transactional semantics in storage management, which is the transactional object storage interface.
