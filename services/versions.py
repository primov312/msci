from fastapi import APIRouter, HTTPException
from datetime import datetime
from typing import List, Set
import httpx

router = APIRouter()

@router.get("/versions")
async def get_versions(name: str):
    try:
        versions = await result_list(name)

        if not versions:
            return {
                "name": name,
                "versions": [],
                "timestamp": datetime.now().isoformat(),
                "message": "No vulnerable versions found for the specified package"
            }

        return {
            "name": name,
            "versions": versions,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

async def result_list(package_name: str) -> List[str]:
    versions = set()
    ubuntu_versions = await name_insert(package_name)
    debian_versions = await query_for_debian(package_name)
    versions.update(ubuntu_versions)
    versions.update(debian_versions)
    return sorted(versions)

async def name_insert(package_name: str) -> List[str]:
    return await query_for_ubuntu(package_name, "Ubuntu")

async def query_for_ubuntu(package_name: str, ecosystem: str) -> List[str]:
    if ecosystem != "Ubuntu":
        raise ValueError("This function is intended only for the Ubuntu ecosystem.")

    url = "https://api.osv.dev/v1/query"
    versions = set()

    async with httpx.AsyncClient() as client:
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        response = await client.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            for item in data.get('vulns', []):
                for affected in item.get('affected', []):
                    versions.update(affected.get('versions', []))
                    if 'ecosystem_specific' in affected:
                        binaries = affected['ecosystem_specific'].get('binaries', [])
                        for binary in binaries:
                            versions.update(binary.values())
        else:
            print(f"Error {response.status_code} for {ecosystem}: {response.text}")

    return sorted(versions)

async def query_for_debian(package_name: str) -> List[str]:
    url = "https://api.osv.dev/v1/query"
    ecosystem = "Debian"
    extracted_versions = set()

    async with httpx.AsyncClient() as client:
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        response = await client.post(url, json=payload)

        if response.status_code == 200:
            data = response.json()
            for vulnerability in data.get('vulns', []):
                for affected_package in vulnerability.get('affected', []):
                    if 'ranges' in affected_package:
                        for range_entry in affected_package['ranges']:
                            if 'events' in range_entry:
                                for event in range_entry['events']:
                                    if 'fixed' in event:
                                        extracted_versions.add(event['fixed'])
        else:
            print(f"Error {response.status_code} for {ecosystem}: {response.text}")
            return []

    return sorted(extracted_versions)
