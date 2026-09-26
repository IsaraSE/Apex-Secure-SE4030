import { Request, Response } from "express";
import Inventory from "../models/Inventory";

export const getAllInventory = async (req: Request, res: Response): Promise<void> => {
  try {

    // [SECURITY][V6] VULNERABLE: NoSQL injection - req.query values are used in the Mongo filter without type checking (e.g. ?status[$ne]=x). OWASP A03:2021
    const { search, category, sport, condition } = req.query;

    const query: any = {};
    if (search) {
      query.$or = [
        { itemName: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }
    if (category) query.category = category;
    if (sport) query.sport = sport;
    if (condition) query.condition = condition;

    // [SECURITY][V6] VULNERABLE: unsanitized query object is passed directly to Inventory.find(). OWASP A03:2021
    const items = await Inventory.find(query).sort({ createdAt: -1 });

    const itemsWithAlerts = items.map((item) => ({
      ...item.toObject(),
      isOutOfStock: item.currentStock === 0,
      isLowStock: item.currentStock > 0 && item.currentStock <= item.minThreshold,
    }));

    res.json(itemsWithAlerts);
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch inventory", error: error.message });
  }
};

export const createInventoryItem = async (req: Request, res: Response): Promise<void> => {
  try {
    const initialStock = Number(req.body.currentStock ?? 0);
    const item = await Inventory.create({
      ...req.body,
      usageHistory:
        initialStock > 0
          ? [
            {
              date: new Date(),
              type: "in",
              change: initialStock,
              previousStock: 0,
              newStock: initialStock,
              reason: "Initial stock",
            },
          ]
          : [],
    });
    res.status(201).json({ message: "Item added successfully", item });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to add item", error: error.message });
  }
};

export const updateInventoryItem = async (req: Request, res: Response): Promise<void> => {
  try {
    const existingItem = await Inventory.findById(req.params.id);

    if (!existingItem) {
      res.status(404).json({ message: "Item not found" });
      return;
    }

    const updatePayload: any = { ...req.body };
    let pushOperation: any;
    const nextStock =
      typeof req.body.currentStock === "number" ? req.body.currentStock : existingItem.currentStock;

    if (nextStock !== existingItem.currentStock) {
      const change = nextStock - existingItem.currentStock;
      pushOperation = {
        usageHistory: {
          date: new Date(),
          type: change > 0 ? "in" : "out",
          change,
          previousStock: existingItem.currentStock,
          newStock: nextStock,
          reason: req.body.adjustmentReason || "Stock update",
        },
      };
      delete updatePayload.adjustmentReason;
    }

    const item = await Inventory.findByIdAndUpdate(
      req.params.id,
      { $set: updatePayload, ...(pushOperation ? { $push: pushOperation } : {}) },
      { new: true, runValidators: true }
    );

    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }

    res.json({ message: "Item updated successfully", item });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to update item", error: error.message });
  }
};

export const deleteInventoryItem = async (req: Request, res: Response): Promise<void> => {
  try {
    const item = await Inventory.findByIdAndDelete(req.params.id);
    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }
    res.json({ message: "Item deleted successfully" });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to delete item", error: error.message });
  }
};

export const getLowStockAlerts = async (_req: Request, res: Response): Promise<void> => {
  try {
    const items = await Inventory.find({
      $expr: { $lte: ["$currentStock", "$minThreshold"] },
    }).sort({ currentStock: 1 });

    res.json({
      count: items.length,
      items: items.map((item) => ({
        id: item._id,
        itemName: item.itemName,
        category: item.category,
        currentStock: item.currentStock,
        minThreshold: item.minThreshold,
        sport: item.sport,
        isOutOfStock: item.currentStock === 0,
        isLowStock: item.currentStock > 0 && item.currentStock <= item.minThreshold,
        deficit: item.minThreshold - item.currentStock,
      })),
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch alerts", error: error.message });
  }
};
