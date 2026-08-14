import httpx
import asyncio
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import uvicorn

app = FastAPI()

class Dependency(BaseModel):
    name: str
    version: str

class AuditRequest(BaseModel):
    dependencies: List[Dependency]

async def query_osv_api(client: httpx.AsyncClient, package_name: str, package_version: str) -> tuple[int, List[str]]:
    """
    Query the OSV API for vulnerabilities and calculate risk score.
    Returns a tuple of (score, flags).
    """
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        },
        "version": package_version
    }

    try:
        response = await client.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=10.0  # 10 second timeout
        )

        # Handle 404 (package not found in OSV)
        if response.status_code == 404:
            return 90, ['unverified-in-osv']

        # Raise exception for other HTTP errors
        response.raise_for_status()

        data = response.json()
        vulns = data.get('vulns', [])

        # Calculate score based on number of vulnerabilities
        vuln_count = len(vulns)
        if vuln_count == 0:
            return 100, []  # No vulnerabilities
        elif 1 <= vuln_count <= 2:
            return 60, ['has-known-cves']  # 1-2 vulnerabilities
        else:  # 3+ vulnerabilities
            return 20, ['critical-risk', 'has-known-cves']

    except httpx.TimeoutException:
        # Handle timeout specifically
        return 50, ['osv-timeout']  # Middle score with timeout flag
    except httpx.HTTPStatusError as e:
        # Handle other HTTP errors (except 404 which we handled above)
        if e.response.status_code == 404:
            return 90, ['unverified-in-osv']
        else:
            # For other HTTP errors, return a lower score with error flag
            return 30, ['osv-api-error']
    except Exception as e:
        # Handle any other exceptions (network issues, JSON parsing, etc.)
        return 30, ['osv-query-failed']

@app.post("/api/v1/audit")
async def audit_dependencies(request: AuditRequest):
    """
    Audit a list of dependencies by querying the OSV API for vulnerabilities and calculating risk scores.
    """
    async with httpx.AsyncClient() as client:
        tasks = []
        for dep in request.dependencies:
            task = query_osv_api(client, dep.name, dep.version)
            tasks.append(task)

        # Execute all OSV queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        dependency_results = []
        overall_score = 0
        count = 0

        for dep, result in zip(request.dependencies, results):
            if isinstance(result, Exception):
                # If the OSV query failed completely, we still want to return something
                score, flags = 30, ['osv-query-failed']
            else:
                score, flags = result  # This is the tuple (score, flags) from query_osv_api

            dependency_results.append({
                "name": dep.name,
                "version": dep.version,
                "score": score,
                "flags": flags
            })
            overall_score += score
            count += 1

        if count == 0:
            overall_score = 0
        else:
            overall_score = round(overall_score / count, 1)

        return {
            "overall_score": overall_score,
            "dependencies": dependency_results
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)