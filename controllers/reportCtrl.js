const Audit = require('../models/Audit');

// GET all reports
const getReports = async (req, res) => {
  try {
    const { severity, language, search } = req.query;
    let query = {};

    if (language) query.language = language;
    if (severity) query['findings.severity'] = severity;

    const reports = await Audit.find(query)
      .select('-sourceCode')
      .sort({ createdAt: -1 })
      .limit(50);

    res.json({ success: true, count: reports.length, data: reports });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// GET single report
const getReportById = async (req, res) => {
  try {
    const report = await Audit.findById(req.params.id);
    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }
    res.json({ success: true, data: report });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// DELETE report
const deleteReport = async (req, res) => {
  try {
    await Audit.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Report deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { getReports, getReportById, deleteReport };
