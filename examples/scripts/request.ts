// Synthetic static-analysis fixture; do not execute during analysis.
function request(url: string): Promise<Response> {
  return fetch(url);
}
