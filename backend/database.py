from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from .models import AttackRecord, AttackSummary, DatabaseConfig

logger = logging.getLogger(__name__)


class MongoDBHandler:
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        self.collection = None

    async def connect(self):
        """Connect to MongoDB"""
        try:
            self.client = AsyncIOMotorClient(self.config.mongodb_uri)
            self.db = self.client[self.config.database_name]
            self.collection = self.db[self.config.collection_name]
            
            # Create indexes for better performance
            await self.collection.create_index("src_ip")
            await self.collection.create_index("timestamp")
            await self.collection.create_index("dst_service")
            
            logger.info(f"Connected to MongoDB: {self.config.database_name}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise

    async def disconnect(self):
        """Disconnect from MongoDB"""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")

    async def insert_attack(self, attack: AttackRecord) -> str:
        """Insert a new attack record"""
        try:
            result = await self.collection.insert_one(attack.dict(by_alias=True))
            logger.info(f"Inserted attack record: {result.inserted_id}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to insert attack record: {e}")
            raise

    async def get_recent_attacks(self, hours: int = 24, limit: int = 100) -> List[AttackRecord]:
        """Get recent attacks from the last N hours"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            cursor = self.collection.find(
                {"timestamp": {"$gte": cutoff_time}}
            ).sort("timestamp", -1).limit(limit)
            
            attacks = []
            async for doc in cursor:
                attacks.append(AttackRecord(**doc))
            
            return attacks
        except Exception as e:
            logger.error(f"Failed to get recent attacks: {e}")
            return []

    async def get_attack_summary(self, hours: int = 24) -> AttackSummary:
        """Get attack summary statistics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Total attacks
            total_attacks = await self.collection.count_documents(
                {"timestamp": {"$gte": cutoff_time}}
            )
            
            # Unique IPs
            unique_ips = len(await self.collection.distinct(
                "src_ip", {"timestamp": {"$gte": cutoff_time}}
            ))
            
            # Service breakdown
            pipeline = [
                {"$match": {"timestamp": {"$gte": cutoff_time}}},
                {"$group": {"_id": "$dst_service", "count": {"$sum": 1}}}
            ]
            service_breakdown = {}
            async for doc in self.collection.aggregate(pipeline):
                service_breakdown[doc["_id"]] = doc["count"]
            
            # Recent attacks
            recent_attacks = await self.get_recent_attacks(hours, 10)
            
            # Top attackers
            pipeline = [
                {"$match": {"timestamp": {"$gte": cutoff_time}}},
                {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            top_attackers = []
            async for doc in self.collection.aggregate(pipeline):
                top_attackers.append({
                    "ip": doc["_id"],
                    "attack_count": doc["count"]
                })
            
            return AttackSummary(
                total_attacks=total_attacks,
                unique_ips=unique_ips,
                service_breakdown=service_breakdown,
                recent_attacks=recent_attacks,
                top_attackers=top_attackers
            )
        except Exception as e:
            logger.error(f"Failed to get attack summary: {e}")
            return AttackSummary(
                total_attacks=0,
                unique_ips=0,
                service_breakdown={},
                recent_attacks=[],
                top_attackers=[]
            )

    async def get_attacks_by_ip(self, src_ip: str, hours: int = 24) -> List[AttackRecord]:
        """Get all attacks from a specific IP"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            cursor = self.collection.find({
                "src_ip": src_ip,
                "timestamp": {"$gte": cutoff_time}
            }).sort("timestamp", -1)
            
            attacks = []
            async for doc in cursor:
                attacks.append(AttackRecord(**doc))
            
            return attacks
        except Exception as e:
            logger.error(f"Failed to get attacks by IP: {e}")
            return []

    async def get_attacks_by_service(self, service: str, hours: int = 24) -> List[AttackRecord]:
        """Get all attacks on a specific service"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            cursor = self.collection.find({
                "dst_service": service,
                "timestamp": {"$gte": cutoff_time}
            }).sort("timestamp", -1)
            
            attacks = []
            async for doc in cursor:
                attacks.append(AttackRecord(**doc))
            
            return attacks
        except Exception as e:
            logger.error(f"Failed to get attacks by service: {e}")
            return []


# Global database instance
db_handler: Optional[MongoDBHandler] = None


async def get_db_handler() -> MongoDBHandler:
    """Get the global database handler instance"""
    global db_handler
    if db_handler is None:
        config = DatabaseConfig()
        db_handler = MongoDBHandler(config)
        await db_handler.connect()
    return db_handler
