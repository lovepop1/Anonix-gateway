"""Optional demo upstream API for evaluating Anonix Gateway reverse-proxy masking."""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Anonix Demo Upstream (Mock Hospital & Student API)")

_STUDENTS = {
    "101": {
        "id": "101",
        "name": "Aarav Sharma",
        "email": "aarav.sharma@university.edu",
        "ssn": "123-45-6789",
        "gpa": 3.91,
        "fee_balance": 1250.00,
        "department": "Computer Science",
    },
    "102": {
        "id": "102",
        "name": "Priya Nair",
        "email": "priya.nair@university.edu",
        "ssn": "987-65-4321",
        "gpa": 3.78,
        "fee_balance": 0.00,
        "department": "Data Science",
    },
}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/students/{student_id}")
def get_student(student_id: str) -> dict[str, object]:
    return _STUDENTS.get(
        student_id,
        {
            "id": student_id,
            "name": "Sample Student",
            "email": f"student{student_id}@university.edu",
            "ssn": "555-01-9999",
            "gpa": 3.5,
            "fee_balance": 400.0,
            "department": "Engineering",
        },
    )
