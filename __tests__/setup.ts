import { jest } from '@jest/globals';

// Global test setup
beforeAll(() => {
	// Set test environment variables
	process.env.NODE_ENV = 'test';
	process.env.LIT_PROTOCOL_DEBUG = 'false';

	console.log('🔧 Global test setup completed');
});

afterAll(() => {
	console.log('🧹 Global test cleanup completed');
});

// Global error handler for unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
	console.error('Unhandled Rejection at:', promise, 'reason:', reason);
	// Don't exit the process in tests, just log
});

// Increase timeout for all tests globally
jest.setTimeout(60000);
