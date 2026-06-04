const mongoose = require('mongoose');

const findingSchema = new mongoose.Schema({
  name: String,
  severity: { type: String, enum: ['High', 'Medium', 'Low'] },
  description: String,
  impact: String,
  recommendation: String,
  secureExample: String,
  lineNumber: Number,
});

const auditSchema = new mongoose.Schema(
  {
    language: {
      type: String,
      required: true,
      enum: ['javascript', 'python', 'java', 'cpp', 'php'],
    },
    sourceCode: {
      type: String,
      required: true,
    },
    findings: [findingSchema],
    securityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
    },
    totalVulnerabilities: {
      type: Number,
      default: 0,
    },
    highCount: { type: Number, default: 0 },
    mediumCount: { type: Number, default: 0 },
    lowCount: { type: Number, default: 0 },
    riskLevel: {
      type: String,
      enum: ['Critical', 'High', 'Medium', 'Low', 'Safe'],
      default: 'Safe',
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Audit', auditSchema);
