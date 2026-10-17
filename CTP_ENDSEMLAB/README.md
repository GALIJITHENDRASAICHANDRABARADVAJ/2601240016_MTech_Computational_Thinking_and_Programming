# Stack and Queue - Web Browser Simulation

## Problem Statement

A web browser maintains recently visited pages using a **Stack**, while downloads are processed using a **Queue**.

Develop a reusable Python package implementing Stack and Queue with type hints and dataclasses.

The program must demonstrate:
- Visiting web pages using `push()`
- Going back using `pop()`
- Viewing the current page using `peek()`
- Adding download requests using `enqueue()`
- Processing downloads using `dequeue()`

## Concept Identification

**Data Structures:** Stack (LIFO) and Queue (FIFO)

**Technique:** Abstract Data Types implemented as reusable, generic dataclasses

**Problem Type:** Data Structure Design and Application

| Structure | Principle | Browser use | Operations |
|---|---|---|---|
| Stack | Last In, First Out | Page history (latest page is on top) | `push`, `pop`, `peek` |
| Queue | First In, First Out | Downloads (earliest request is processed first) | `enqueue`, `dequeue`, `peek` |

## Package Structure

```text
.
|-- Program.py                 Demonstration program
|-- README.md
|-- ds_package/
|   |-- __init__.py            Public exports
|   |-- stack.py               Stack[T] dataclass
|   |-- fifo_queue.py          Queue[T] dataclass
|   |-- browser.py             WebPage, DownloadRequest, BrowserHistory, DownloadManager
|   `-- exceptions.py          EmptyStructureError
`-- tests/
    `-- test_structures.py     9 unit tests
```

## Design Decisions

- **Generic types:** `Stack[T]` and `Queue[T]` use `TypeVar` and `Generic`, so one implementation holds pages, numbers, strings or any other type (`Stack[int]`, `Queue[str]`).
- **Dataclasses:** `Stack`, `Queue`, `BrowserHistory` and `DownloadManager` are `@dataclass` classes using `field(default_factory=...)`, so every instance gets its own storage. `WebPage` and `DownloadRequest` are `frozen=True` dataclasses, so records cannot change after creation.
- **Efficient storage:** The Stack uses a Python `list` (the end of the list is the top). The Queue uses `collections.deque`, because `list.pop(0)` is O(n) while `deque.popleft()` is O(1).
- **Safe errors:** Removing or peeking on an empty structure raises a clear `EmptyStructureError` instead of an unclear `IndexError`.
- **Back button rule:** `BrowserHistory.back()` pops the current page and returns the previous one. The first page cannot be left, so a page is always shown.

## Procedure

1. Define a generic `Stack[T]` dataclass with `push`, `pop` and `peek`.
2. Define a generic `Queue[T]` dataclass with `enqueue`, `dequeue` and `peek`.
3. Define `WebPage` and `DownloadRequest` dataclasses to represent browser data.
4. Build `BrowserHistory` on a Stack and `DownloadManager` on a Queue.
5. Visit pages with `push()`.
6. View the current page with `peek()`.
7. Go back with `pop()`.
8. Add downloads with `enqueue()`.
9. Process downloads with `dequeue()` in the order they were requested.
10. Demonstrate error handling and reuse with other data types.

## Implementation

The complete executable demonstration is provided in `Program.py`. The reusable package is in the `ds_package/` folder.

Example usage:

```python
from ds_package import Stack, Queue

pages: Stack[str] = Stack()
pages.push("Home")
pages.push("Docs")
pages.peek()      # "Docs"
pages.pop()       # "Docs"

downloads: Queue[str] = Queue()
downloads.enqueue("a.pdf")
downloads.enqueue("b.zip")
downloads.dequeue()   # "a.pdf"
```

## Input

- Pages visited: Home, Search Results, Python Docs, Tutorial
- Download requests: report.pdf (2.5 MB), photo.png (1.2 MB), setup.zip (45.0 MB)

## Output

```text
============================================================
WEB BROWSER - STACK AND QUEUE DEMONSTRATION
============================================================

1. VISITING WEB PAGES USING push()
------------------------------------------------------------
Visited : Home            (https://example.com)
Visited : Search Results  (https://example.com/search?q=python)
Visited : Python Docs     (https://example.com/docs/python)
Visited : Tutorial        (https://example.com/docs/python/tutorial)
History (top -> bottom): Tutorial | Python Docs | Search Results | Home

2. VIEWING THE CURRENT PAGE USING peek()
------------------------------------------------------------
Current page : Tutorial (https://example.com/docs/python/tutorial)
Stack size   : 4

3. GOING BACK USING pop()
------------------------------------------------------------
Left "Tutorial"  ->  now viewing "Python Docs"
Left "Python Docs"  ->  now viewing "Search Results"
History (top -> bottom): Search Results | Home
Current page : Search Results

4. ADDING DOWNLOAD REQUESTS USING enqueue()
------------------------------------------------------------
Queued  : report.pdf   (2.5 MB)
Queued  : photo.png    (1.2 MB)
Queued  : setup.zip    (45.0 MB)
Pending (front -> back): report.pdf | photo.png | setup.zip
Next in line : report.pdf

5. PROCESSING DOWNLOADS USING dequeue()
------------------------------------------------------------
Downloaded : report.pdf   (2.5 MB)
Downloaded : photo.png    (1.2 MB)
Downloaded : setup.zip    (45.0 MB)
Pending (front -> back): empty

6. EDGE CASES
------------------------------------------------------------
Empty queue  -> dequeue from an empty queue
First page   -> no earlier page to go back to
Reusable     -> Stack[int] top = 20 | Queue[str] front = job-1

Operation Complexity (all O(1)):
Stack : push, pop, peek
Queue : enqueue, dequeue, peek

Space Complexity: O(n)
Where n = number of stored items
```

## Complexity Analysis

### Time Complexity

| Structure | Operation | Time |
|---|---|---|
| Stack | `push`, `pop`, `peek` | O(1) |
| Queue | `enqueue`, `dequeue`, `peek` | O(1) |

### Space Complexity

Each structure stores `n` items.

**Space Complexity: O(n)**

## Testing

```bash
python -m unittest discover -s tests -v
```

The 9 tests check LIFO order, FIFO order, empty-structure errors, that `peek()` does not remove an item, that separate instances do not share data, the back-button rule, and download order.

## Conclusion

A Stack suits browser history because the most recently visited page must be the first one revisited (Last In, First Out). A Queue suits downloads because requests must be handled fairly in the order they arrive (First In, First Out).

The package is generic, type-hinted and built on dataclasses, so the same `Stack` and `Queue` can be reused in other programs.

## Execution

Run the program from the project folder using:

```bash
python Program.py
```

Requires Python 3.9 or later. No external Python packages are required.
