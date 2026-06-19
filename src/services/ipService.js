import axios from "axios";

const TOKEN = "2c4a33f69939b6";

export const fetchIpData = async (ip) => {
  const response = await axios.get(
    `https://ipinfo.io/${ip}?token=${TOKEN}`
  );

  return response.data;
};