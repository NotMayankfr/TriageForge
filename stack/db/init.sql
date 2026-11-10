-- TriageForge Seed Database
CREATE TABLE IF NOT EXISTS items (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO items (name, category, status) VALUES
    ('LoanWatch Loan Underwriting Service', 'FinTech', 'active'),
    ('Kafka Event Streaming Consumer', 'Infrastructure', 'active'),
    ('Postgres Connection Broker', 'Database', 'active'),
    ('UAT Staging Gateway', 'Internal', 'active')
ON CONFLICT DO NOTHING;
