from pathlib import Path

import face_recognition as fr
import numpy as np

type FaceEmbedding = np.ndarray


def norm_face_embedding(image_path: Path) -> FaceEmbedding:
    face_image = fr.load_image_file(image_path)
    face_embeddings = fr.face_encodings(face_image)
    if len(face_embeddings) != 1:
        raise Exception(f"Found {len(face_embeddings)} faces, expected 1: {image_path}")

    norm_face_embedding = face_embeddings[0] / np.linalg.norm(face_embeddings[0])
    return norm_face_embedding
