const express = require('express');
const router = express.Router();
const { getReports, getReportById, deleteReport } = require('../controllers/reportCtrl');

// GET /api/reports
router.get('/', getReports);

// GET /api/reports/:id
router.get('/:id', getReportById);

// DELETE /api/reports/:id
router.delete('/:id', deleteReport);

module.exports = router;
