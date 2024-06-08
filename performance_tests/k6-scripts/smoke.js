import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  // A number specifying the number of VUs to run concurrently.
  vus: 10,
  // A string specifying the total duration of the test run.
  duration: '30s',

};

export default function() {
  const url =  __ENV.API_ENDPOINT || "http://192.168.86.147:30001/api/dogs"


  // Defines the dog in a JSON object
  const payload = JSON.stringify({
    dog: {
      breed: "123",
      weight: 123
    }
  })

  // HTTP request parameters
  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  // Sends an HTTP POST request to the HTTP server to store the dog object
  const res = http.post(url, payload, params);

  // Extracts the ID assinged by the HTTP server
  const id = JSON.parse(res.body)["data"]["id"]
  
  // Stops the test execution for 1 second
  sleep(1);
  // Fetches the previously stored dog from the HTTP server
  http.get(`${url}/${id}`)
  // Stops the test execution for 0.5 second
  sleep(0.5);
  // Deletes the previously stored dog from the HTTP server
  http.del(`${url}/${id}`)
  // Stops the test execution for 1 second
  sleep(1);
}
