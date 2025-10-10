# Integration Tests

This directory contains integration tests for `@ratio1/cstore-auth-ts` that test the complete authentication flow with realistic scenarios.

## Overview

Integration tests differ from unit tests in that they:

- **Test full system integration** rather than isolated units
- **Use more realistic mocks** that simulate actual CStore behavior
- **Include proper cleanup workflows** that mirror production patterns
- **Run longer** and test complete user journeys
- **Verify data consistency** across multiple operations

## Running Integration Tests

### Run integration tests only
```bash
npm run test:integration
```

### Run integration tests in watch mode
```bash
npm run test:integration:watch
```

### Run all tests (unit + integration)
```bash
npm run test:all
```

### Run unit tests only (excludes integration)
```bash
npm test
```

## Test Structure

### User Lifecycle Tests
Tests that verify complete user workflows from creation through authentication and retrieval.

- **Full lifecycle**: Create → Authenticate → Retrieve → List all users
- **Multiple users**: Handles batch user creation and retrieval
- **Data integrity**: Ensures metadata and roles are preserved

### getAllUsers Integration Scenarios
Comprehensive tests for the `getAllUsers` method:

- **Typed metadata**: Verifies TypeScript generic types work correctly
- **Empty states**: Handles systems with only bootstrap admin
- **Security**: Ensures no password data leaks
- **Role handling**: Correctly separates admin vs regular users

### Error Handling
Tests for proper error scenarios:

- **Duplicate usernames**: Prevents user conflicts
- **Invalid credentials**: Rejects wrong passwords
- **Invalid usernames**: Validates username format requirements

### Data Consistency
Ensures data integrity across operations:

- **Timestamp consistency**: Verifies timestamps are preserved
- **Metadata preservation**: Ensures custom metadata survives multiple retrievals

### Cleanup Verification
Tests the cleanup mechanisms themselves:

- **Proper cleanup**: Verifies test data is completely removed
- **Null-then-delete pattern**: Follows best practices for data cleanup

## Best Practices Implemented

### 1. Cleanup Strategy

All tests follow a **cleanup-before-and-after** pattern:

```typescript
beforeEach(() => {
  cstore = new IntegrationCStore();
});

afterEach(async () => {
  // Set values to null, then delete
  await cstore.cleanup();
});
```

### 2. Test Isolation

Each test uses a **unique hash key** to prevent interference:

```typescript
function getTestHkey(): string {
  testCounter++;
  return `auth:integration:test:${testCounter}:${Date.now()}`;
}
```

### 3. Null-Before-Delete Pattern

The `IntegrationCStore` implements proper cleanup:

```typescript
async cleanup(): Promise<void> {
  for (const hkey of this.keysToCleanup) {
    const hash = this.store.get(hkey);
    if (hash) {
      // First pass: set all values to null/empty
      for (const key of hash.keys()) {
        await this.hset(hkey, key, '');
      }
      // Second pass: clear the hash
      hash.clear();
    }
    this.store.delete(hkey);
  }
  this.keysToCleanup.clear();
}
```

### 4. Serial Execution

Integration tests run serially (single-threaded) to avoid race conditions:

```typescript
// vitest.integration.config.ts
poolOptions: {
  threads: {
    singleThread: true
  }
}
```

### 5. Extended Timeouts

Integration tests have longer timeouts (30s) since they may involve:
- Password hashing (computationally expensive)
- Multiple sequential operations
- Cleanup workflows

## Writing New Integration Tests

When adding new integration tests, follow this template:

```typescript
it('should test a complete user workflow', async () => {
  // 1. Get unique hash key for isolation
  const hkey = getTestHkey();
  
  // 2. Create auth instance
  const auth = new CStoreAuth({
    client: cstore,
    hkey,
    now: () => new Date('2024-01-01T00:00:00Z')
  });

  // 3. Initialize
  await auth.simple.init();

  // 4. Test your workflow
  await auth.simple.createUser('testuser', 'Pass123!');
  const users = await auth.simple.getAllUsers();
  expect(users.length).toBeGreaterThan(0);

  // 5. Cleanup (always!)
  await cstore.cleanupHash(hkey);
});
```

### Key Guidelines

1. **Always cleanup** at the end of each test
2. **Use unique hash keys** for test isolation
3. **Test complete workflows**, not individual functions
4. **Verify security**: Ensure no secrets leak
5. **Check data consistency** across operations
6. **Use TypeScript types** to catch type errors

## Coverage

Integration tests currently cover:

- ✅ Complete user lifecycle (create, auth, retrieve, list)
- ✅ Batch operations (getAllUsers with multiple users)
- ✅ Error handling (duplicates, invalid credentials, invalid usernames)
- ✅ Data consistency (timestamps, metadata preservation)
- ✅ Security (password hash protection)
- ✅ Cleanup verification

## CI/CD Integration

In CI/CD pipelines, integration tests can be run:

- **Separately**: `npm run test:integration` (for slower integration-only checks)
- **Together**: `npm run test:all` (for comprehensive test runs)

Consider running:
- Unit tests on every commit
- Integration tests on PR merges or before releases

