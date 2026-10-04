SELECT model AS method, SUM(hit) AS hits, COUNT(*) AS runs,
       SUM(hit)*1.0/COUNT(*) AS hit_rate,
       AVG(charged_runtime_s) AS charged_runtime_s,
       AVG(regret) AS regret
FROM frozen_evaluations
GROUP BY model
ORDER BY hit_rate DESC, method;
