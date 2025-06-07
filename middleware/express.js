// Express Middleware Setup for LivePerson IDP Server
import cors from 'cors';
import morgan from 'morgan';
import express from 'express';

/**
 * Setup basic Express middleware
 * @param {Express} app - Express application instance
 */
export function setupExpressMiddleware(app) {
    // CORS middleware
    app.use(cors());
    
    // JSON and URL-encoded body parsing
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    
    // HTTP request logger
    app.use(morgan('combined'));
}

/**
 * Setup basic Express middleware with custom options
 * @param {Express} app - Express application instance
 * @param {Object} options - Middleware configuration options
 */
export function setupExpressMiddlewareWithOptions(app, options = {}) {
    const {
        corsOptions = {},
        jsonOptions = {},
        urlEncodedOptions = { extended: true },
        morganFormat = 'combined'
    } = options;
    
    // CORS middleware with custom options
    app.use(cors(corsOptions));
    
    // JSON and URL-encoded body parsing with custom options
    app.use(express.json(jsonOptions));
    app.use(express.urlencoded(urlEncodedOptions));
    
    // HTTP request logger with custom format
    app.use(morgan(morganFormat));
} 