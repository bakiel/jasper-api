export default function handler(req, res) {
  res.status(200).json({
    status: 'healthy',
    service: 'JASPER Contact API',
    timestamp: new Date().toISOString()
  });
}
