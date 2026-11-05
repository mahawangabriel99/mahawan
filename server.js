require('dotenv').config();

const express = require('express');
const neo4j = require('neo4j-driver');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

const driver = neo4j.driver(
  process.env.NEO4J_URI,
  neo4j.auth.basic(
    process.env.NEO4J_USERNAME,
    process.env.NEO4J_PASSWORD
  )
);

app.get('/', (req, res) => {
  res.send('AlertAgos API is running!');
});

app.get('/health', async (req, res) => {
  try {
    await driver.verifyConnectivity();

    res.json({
      status: 'connected',
      database: 'Neo4j AuraDB',
      application: 'AlertAgos'
    });
  } catch (error) {
    console.error('Database connection failed:', error.message);

    res.status(500).json({
      status: 'error',
      message: 'Database connection failed'
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`AlertAgos API running on port ${PORT}`);
});

process.on('SIGTERM', async () => {
  await driver.close();
  process.exit(0);
});