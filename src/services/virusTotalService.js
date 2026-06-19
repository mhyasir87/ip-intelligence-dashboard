import axios from "axios";

export const fetchVirusTotalData = async (ip) => {
  const response = await axios.get(
    `http://localhost:5000/api/virustotal/${ip}`
  );

  return response.data;
};