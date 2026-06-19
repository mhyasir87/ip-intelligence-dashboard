import axios from "axios";

export const fetchIpData = async (ip) => {
  const response = await axios.get(
  `https://ip-intelligence-dashboard.onrender.com/api/ipinfo/${ip}`
);

  return response.data;
};