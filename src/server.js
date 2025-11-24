const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const scanService = require('./services/scanService');

app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'API is running!' });
});

app.post('/api/scan', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    const result = await scanService.scanURL(url);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed' });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log('SERVER IS RUNNING ON PORT 3000');
});