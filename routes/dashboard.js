const express = require('express');
const router = express.Router();
const Audit = require('../models/Audit');

// GET /api/dashboard - Stats and recent audits
router.get('/', async (req, res) => {
  try {
    const totalAudits = await Audit.countDocuments();

    const severityCounts = await Audit.aggregate([
      {
        $group: {
          _id: null,
          totalHigh: { $sum: '$highCount' },
          totalMedium: { $sum: '$mediumCount' },
          totalLow: { $sum: '$lowCount' },
          avgScore: { $avg: '$securityScore' },
        },
      },
    ]);

    const recentAudits = await Audit.find()
      .select('-sourceCode')
      .sort({ createdAt: -1 })
      .limit(10);

    const languageStats = await Audit.aggregate([
      { $group: { _id: '$language', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    const riskStats = await Audit.aggregate([
      { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
    ]);

    res.json({
      success: true,
      data: {
        totalAudits,
        severityCounts: severityCounts[0] || {
          totalHigh: 0,
          totalMedium: 0,
          totalLow: 0,
          avgScore: 100,
        },
        recentAudits,
        languageStats,
        riskStats,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
