/**
 * Academic Record Model
 * ---------------------
 * Dummy verified credentials for candidates in the academic recruitment portal.
 */

import { dbQuery, dbRun } from './db';

export interface AcademicRecord {
  id: number;
  user_id: number;
  qualification: string;
  institution: string;
  grade_or_class: string;
  completion_year: number;
  credential_hash: string;
  verification_status: string;
  created_at: string;
}

export class AcademicRecordModel {
  static async getByUserId(userId: number): Promise<AcademicRecord[]> {
    return dbQuery<AcademicRecord>(
      'SELECT * FROM academic_records WHERE user_id = ? ORDER BY completion_year DESC',
      [userId]
    );
  }

  static async seedDefaultRecordsForUser(userId: number, fullName: string): Promise<void> {
    const existing = await this.getByUserId(userId);
    if (existing.length === 0) {
      await dbRun(
        `INSERT INTO academic_records (user_id, qualification, institution, grade_or_class, completion_year, credential_hash, verification_status)
         VALUES 
         (?, 'M.Sc. in Information Technology', 'Federal University Lokoja', 'First Class Honours', 2022, 'SHA256: 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce', 'VERIFIED'),
         (?, 'B.Sc. in Software Engineering', 'University of Ilorin', 'Second Class Upper', 2018, 'SHA256: c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'VERIFIED'),
         (?, 'Advanced Diploma in Network Security', 'National Open University', 'Distinction', 2019, 'SHA256: 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b', 'VERIFIED')`,
        [userId, userId, userId]
      );
    }
  }
}
