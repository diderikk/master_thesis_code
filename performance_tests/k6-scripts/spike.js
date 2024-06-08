import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
	thresholds: {
    http_req_failed: [{ threshold: 'rate<0.05', abortOnFail: true }],
    http_req_duration: ['p(99)<1000'], 
  },

  stages: [
    { duration: '2m', target: 1500 }, 

    { duration: '1m', target: 0 },
  ],
};

export default function() {
  const url =  __ENV.API_ENDPOINT || "http://192.168.86.147:30001/api/dogs"
  const payload = JSON.stringify({
    dog: {
      breed: "123",
      weight: 123
    }
  })

	const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const res = http.post(url, payload, params);
	if(res.status == 201){
		const id = JSON.parse(res.body)["data"]["id"]
  
		sleep (1);
		http.get(`${url}/${id}`)
		sleep(0.5);
		http.del(`${url}/${id}`)
		sleep(1);
	}
}
