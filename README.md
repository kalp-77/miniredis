# MiniRedis

MiniRedis is a small, Redis-inspired in-memory key-value store written in C++.  
It’s intended for learning: networking, custom data structures, and system programming.

---

## Features

- In-memory key-value storage with custom hashmap
- TCP server with non-blocking I/O
- Event-driven architecture using `poll()`
- Basic Redis-like commands (GET, SET, DEL, TYPE)
- String and integer data types

--- 

## Architecture

### Components

1. **Server (`server_end.cpp`)**
   - TCP server implementation
   - Non-blocking I/O with `poll()`
   - Connection state management
   - Parses requests and emits responses

2. **Client (`client_end.cpp`)**
   - Simple TCP client
   - Command-line interface

3. **Custom Hashmap (`hashtab.h`, `hashmap.cpp`)**
   - Open addressing with chaining for collisions
   - Progressive resizing

### Data Structures

1. **Hashmap Implementation**
   ```cpp
   struct HNode {
       HNode *next = NULL;
       uint64_t hcode = 0;
   };

   struct HTab {
       HNode **tab = NULL;
       size_t mask = 0;
       size_t size = 0;
   };

   struct HMap {
       HTab ht1;  // current
       HTab ht2;  // old
       size_t resizing_pos = 0;
   };
   ```

2. **Key-Value Entry**
   ```cpp
   struct Entry {
       HNode node;
       std::string key;
       std::string val;
   };
   ```

### Protocol

The server uses a binary protocol for communication:

1. **Request Format**
   - 4 bytes: total message length
   - 4 bytes: number of arguments
   - For each argument:
     - 4 bytes: argument length
     - N bytes: argument data

2. **Response Format**
   - 4 bytes: response code
   - N bytes: response data

## Building

### Compilation

1. Compile the server:
   ```bash
   g++ -o server server_end.cpp hashmap.cpp -std=c++11
   ```

2. Compile the client:
   ```bash
   g++ -o client client_end.cpp -std=c++11
   ```

3. Start the server:
   ```bash
   ./server
   ```

4. Use the client to interact with the server:
   ```bash
   # Set a string value
   ./client set mykey myvalue

   # Set an integer value
   ./client set myint 42

   # Get a value
   ./client get mykey
   ./client get myint

   # Check the type of a value
   ./client type mykey
   ./client type myint

   # Delete a key
   ./client del mykey
   ```

## Implementation Details

### Server Architecture
   - Non-blocking sockets
   - Event-driven using `poll()`
   - Binary parser → command execution → binary reply
   - Command validation
   - Response generation

### Client Architecture
   - CLI argument parsing
   - Binary protocol formatting
   - Reads and displays server replies

## Performance Considerations

1. **Hashmap Design**
   - progressive resizing avoids long pause times

2. **Network I/O**
   - non-blocking read/write keeps multiple connections responsive
