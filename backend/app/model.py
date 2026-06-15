from datetime import datetime
from typing import Optional, List, Any, Dict
from uuid import UUID

from pydantic import BaseModel, Field

# -----------------------
# Shared base primitives
# -----------------------

class ObjectBase(BaseModel):
    object_id: UUID
    created_at: datetime
    creating_user_object_id: UUID


class VersionBase(BaseModel):
    version_id: str = Field(..., max_length=1024)
    object_id: UUID
    created_at: datetime
    creating_user_object_id: UUID
    is_tombstone: bool = False


# -----------------------
# Version payload tables
# -----------------------

class UserVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    password_hashed: Optional[str] = None


class LogVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    operation: Dict[str, Any]


# -----------------------
# Media / content types
# -----------------------

class ImageVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    image: bytes
    embedding: List[float] = Field(..., description="vector(1536)")


class ArticleVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    background_image_object_id: UUID
    main_image_object_id: UUID
    main_text: str


# -----------------------
# Forum
# -----------------------

class ForumThreadVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    parent_object_id: UUID
    is_leaf: bool = True
    description: str


class ForumPostVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    forum_thread_object_id: UUID
    reply_to_forum_post_object_id: Optional[UUID] = None
    main_text: str


# -----------------------
# Chat
# -----------------------

class ChatMessageVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    reply_to_message_object_id: UUID
    domain_name: str


# -----------------------
# Notebook
# -----------------------

class NotebookVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    description: str


class NotebookCellVersion(BaseModel):
    version_id: str = Field(..., max_length=1024)
    notebook_object_id: UUID
    is_hideable: bool
    main_code: str
