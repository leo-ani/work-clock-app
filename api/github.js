export default async function handler(req, res) {
  console.log('API called');
  return res.status(200).json({ message: 'OK' });
}
