"""
SAT-SA Detectors Package.

Each detector (G1-G6) is implemented as a standalone module.
All detectors return a list of DetectorResult objects.

DetectorResult schema guarantees that every finding includes:
  - The test name and statistical parameters
  - The statistic and p-value/score
  - A confidence/limitations note
  - Linked record IDs (alert, case, analyst)

This satisfies the explainability requirement: every flag must show
the test used, parameters, statistic, p-value/score, and the exact
underlying Case IDs / Alert IDs / Analyst IDs.
"""
