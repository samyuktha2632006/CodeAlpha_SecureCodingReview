const express = require('express');
const router = express.Router();
const Audit = require('../models/Audit');
const { analyzeCode } = require('../controllers/analyzeCtrl');

// POST /api/analyze - Analyze code and return findings
router.post('/', async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code || !language) {
      return res.status(400).json({
        success: false,
        message: 'Code and language are required',
      });
    }

    const result = analyzeCode(code, language);

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// POST /api/analyze/save - Save audit report to DB
router.post('/save', async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code || !language) {
      return res.status(400).json({
        success: false,
        message: 'Code and language are required',
      });
    }

    const result = analyzeCode(code, language);

    const audit = await Audit.create({
      language,
      sourceCode: code,
      ...result,
    });

    res.status(201).json({ success: true, data: audit });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
