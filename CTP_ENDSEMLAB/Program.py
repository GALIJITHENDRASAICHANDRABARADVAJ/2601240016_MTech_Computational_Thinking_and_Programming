# Web Browser - Stack (history) and Queue (downloads)

from ds_package import (
    BrowserHistory,
    DownloadManager,
    DownloadRequest,
    EmptyStructureError,
    Queue,
    Stack,
    WebPage,
)


def show_history(history: BrowserHistory) -> None:
    print('History (top -> bottom):', ' | '.join(p.title for p in history.pages))


def show_downloads(manager: DownloadManager) -> None:
    print('Pending (front -> back):', ' | '.join(d.filename for d in manager.pending) or 'empty')


print('=' * 60)
print('WEB BROWSER - STACK AND QUEUE DEMONSTRATION')
print('=' * 60)

# ---------------------------------------------------------------
# PART 1: Stack - browsing history
# ---------------------------------------------------------------
history = BrowserHistory()

print('\n1. VISITING WEB PAGES USING push()')
print('-' * 60)
for page in [
    WebPage('Home', 'https://example.com'),
    WebPage('Search Results', 'https://example.com/search?q=python'),
    WebPage('Python Docs', 'https://example.com/docs/python'),
    WebPage('Tutorial', 'https://example.com/docs/python/tutorial'),
]:
    history.visit(page)
    print(f'Visited : {page.title:<15} ({page.url})')
show_history(history)

print('\n2. VIEWING THE CURRENT PAGE USING peek()')
print('-' * 60)
current = history.current()
print(f'Current page : {current.title} ({current.url})')
print('Stack size   :', history.pages.size())

print('\n3. GOING BACK USING pop()')
print('-' * 60)
for _ in range(2):
    left = history.current()
    shown = history.back()
    print(f'Left "{left.title}"  ->  now viewing "{shown.title}"')
show_history(history)
print(f'Current page : {history.current().title}')

# ---------------------------------------------------------------
# PART 2: Queue - download requests
# ---------------------------------------------------------------
manager = DownloadManager()

print('\n4. ADDING DOWNLOAD REQUESTS USING enqueue()')
print('-' * 60)
for request in [
    DownloadRequest('report.pdf', 'https://example.com/files/report.pdf', 2.5),
    DownloadRequest('photo.png', 'https://example.com/files/photo.png', 1.2),
    DownloadRequest('setup.zip', 'https://example.com/files/setup.zip', 45.0),
]:
    manager.add(request)
    print(f'Queued  : {request.filename:<12} ({request.size_mb} MB)')
show_downloads(manager)
print('Next in line :', manager.next_in_line().filename)

print('\n5. PROCESSING DOWNLOADS USING dequeue()')
print('-' * 60)
while not manager.pending.is_empty():
    done = manager.process_next()
    print(f'Downloaded : {done.filename:<12} ({done.size_mb} MB)')
show_downloads(manager)

# ---------------------------------------------------------------
# PART 3: Empty-structure handling and reuse with other types
# ---------------------------------------------------------------
print('\n6. EDGE CASES')
print('-' * 60)
try:
    manager.process_next()
except EmptyStructureError as error:
    print('Empty queue  ->', error)

try:
    history.back()
    history.back()
    history.back()
except EmptyStructureError as error:
    print('First page   ->', error)

numbers: Stack[int] = Stack()
numbers.push(10)
numbers.push(20)
jobs: Queue[str] = Queue()
jobs.enqueue('job-1')
print('Reusable     -> Stack[int] top =', numbers.peek(), '| Queue[str] front =', jobs.peek())

print('\nOperation Complexity (all O(1)):')
print('Stack : push, pop, peek')
print('Queue : enqueue, dequeue, peek')
print('\nSpace Complexity: O(n)')
print('Where n = number of stored items')
