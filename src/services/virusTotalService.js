import axios from "axios";

export const fetchVirusTotalData = async (ip) => {
  const response = await axios.get(
    `https://ip-intelligence-dashboard.onrender.com/api/virustotal/${ip}`
  );

  return response.data;
};