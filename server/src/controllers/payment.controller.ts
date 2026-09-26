import { Request, Response } from "express";
import mongoose from "mongoose";
import Payment from "../models/Payment";
import User from "../models/User";
import { predictAttendance, predictClubProfit } from "../services/prediction.service";
import { AuthRequest } from "../middleware/auth";
import { notifyAdmins } from "../services/notification.service";

const normalizeMethod = (method: string | undefined): "cash" | "card_online" | "bank_transfer" | undefined => {
  if (!method) return undefined;
  if (method === "card" || method === "online") return "card_online";
  return method as "cash" | "card_online" | "bank_transfer";
};

const validateAmountByMethod = (amount: number, method?: string): string | null => {
  if (amount <= 0) {
    return "Payment amount must be greater than zero.";
  }
  return null;
};

export const getAllPayments = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
      // [SECURITY][V6] VULNERABLE: NoSQL injection - req.query values (status, method, memberId, dates) are used in the Mongo filter without type checking (e.g. ?status[$ne]=x). OWASP A03:2021
    const { status, method, startDate, endDate, memberId } = req.query;

    const query: any = {};
    if (status) query.status = status;
    if (method) query.method = method;
    if (req.user?.role === "member") {
      query.memberId = req.user.id;
    } else if (memberId) {
      query.memberId = memberId;
    }
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate as string);
      if (endDate) query.date.$lte = new Date(endDate as string);
    }
    
    // [SECURITY][V6] VULNERABLE: unsanitized query object is passed directly to Payment.find(). OWASP A03:2021
    const payments = await Payment.find(query)
      .populate("memberId", "name email sport")
      .populate("requestedBy", "name email")
      .populate("verifiedBy", "name email")
      .sort({ date: -1 });

    res.json(payments);
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch payments", error: error.message });
  }
};

export const createPayment = async (req: Request, res: Response): Promise<void> => {
  try {
    const { memberId, status = "completed", amount, paymentForMonth } = req.body;
    const method = normalizeMethod(req.body.method);

    const amountError = validateAmountByMethod(amount, method);
    if (amountError) {
      res.status(400).json({ message: amountError });
      return;
    }

    const member = await User.findById(memberId);
    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    const payment = await Payment.create({
      ...req.body,
      method,
      amount,
      paymentForMonth,
    });
    const populated = await payment.populate("memberId", "name email sport");

    if (status === "completed" && member.status !== "active") {
      member.status = "active";
      await member.save();
    }

    if (status === "completed") {
      await notifyAdmins({
        type: "payment_completed",
        title: "Payment Completed",
        message: `${member.name} completed payment for ${paymentForMonth || "the selected month"}.`,
        metadata: {
          memberId: String(member._id),
          paymentId: String(payment._id),
          month: paymentForMonth || null,
        },
      });
    }

    res.status(201).json({ message: "Payment recorded successfully", payment: populated });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to record payment", error: error.message });
  }
};

export const createPaymentRequest = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { memberId, amount, date, description, paymentForMonth, method } = req.body;

    const normalizedMethod = normalizeMethod(method);
    if (normalizedMethod === "bank_transfer") {
      res.status(400).json({
        message: "Payment requests cannot be made with bank transfer. Use cash or Card/Online instead.",
      });
      return;
    }

    const amountError = validateAmountByMethod(amount, normalizedMethod);
    if (amountError) {
      res.status(400).json({ message: amountError });
      return;
    }

    const member = await User.findById(memberId);
    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    const payment = await Payment.create({
      memberId,
      amount,
      date: date ? new Date(date) : new Date(),
      description: description || "Membership fee request",
      paymentForMonth,
      status: "requested",
      requestedBy: req.user?.id,
    });

    const populated = await payment.populate("memberId", "name email sport");
    res.status(201).json({ message: "Payment request created successfully", payment: populated });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to create payment request", error: error.message });
  }
};

export const submitPayment = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const paymentId = req.params.id;
    const memberId = req.user?.id;

    const payment = await Payment.findById(paymentId);
    if (!payment) {
      res.status(404).json({ message: "Payment request not found" });
      return;
    }

    if (payment.memberId.toString() !== memberId) {
      res.status(403).json({ message: "You can only submit your own payment requests." });
      return;
    }

    if (!["requested", "pending"].includes(payment.status)) {
      res.status(400).json({ message: "Only requested or pending payments can be submitted." });
      return;
    }

    const method = normalizeMethod(req.body.method) || "card_online";
    if (!["cash", "card_online"].includes(method)) {
      res.status(400).json({ message: "Members can only submit payments using cash or Card/Online." });
      return;
    }

    const amountError = validateAmountByMethod(payment.amount, method);
    if (amountError) {
      res.status(400).json({ message: amountError });
      return;
    }

    payment.method = method;
    payment.memberReference = req.body.memberReference;
    payment.memberNote = req.body.memberNote;
    payment.paymentForMonth = req.body.paymentForMonth || payment.paymentForMonth;
    payment.slipUrl = req.body.slipUrl;
    payment.status = "submitted";
    if (method === "card_online") {
      payment.paidAt = new Date();
    }
    await payment.save();

    res.json({ message: "Payment submitted successfully", payment });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to submit payment", error: error.message });
  }
};

export const verifyPayment = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const paymentId = req.params.id;
    const { isApproved, verificationNote } = req.body;

    const payment = await Payment.findById(paymentId);
    if (!payment) {
      res.status(404).json({ message: "Payment not found" });
      return;
    }

    if (payment.status !== "submitted") {
      res.status(400).json({ message: "Only submitted payments can be verified." });
      return;
    }

    payment.status = isApproved ? "completed" : "failed";
    if (req.user?.id) {
      payment.verifiedBy = new mongoose.Types.ObjectId(req.user.id);
    }
    payment.verifiedAt = new Date();
    payment.verificationNote = verificationNote;
    await payment.save();

    if (isApproved) {
      const member = await User.findById(payment.memberId);
      if (member && member.status !== "active") {
        member.status = "active";
        await member.save();
      }

      if (member) {
        await notifyAdmins({
          type: "payment_completed",
          title: "Payment Completed",
          message: `${member.name} payment has been marked as paid for ${payment.paymentForMonth || "the selected month"}.`,
          metadata: {
            paymentId: String(payment._id),
            memberId: String(member._id),
            month: payment.paymentForMonth || null,
          },
        });
      }
    }

    const populated = await payment.populate("memberId", "name email sport");

    res.json({
      message: isApproved ? "Payment verified successfully" : "Payment rejected",
      payment: populated,
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to verify payment", error: error.message });
  }
};

export const markCashPaymentAsPaid = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const payment = await Payment.findById(req.params.id);
    if (!payment) {
      res.status(404).json({ message: "Payment not found" });
      return;
    }

    if (payment.method !== "cash") {
      res.status(400).json({ message: "Only cash payments can be manually marked as paid." });
      return;
    }

    payment.status = "completed";
    payment.verifiedBy = req.user?.id ? new mongoose.Types.ObjectId(req.user.id) : undefined;
    payment.verifiedAt = new Date();
    payment.verificationNote = req.body.verificationNote || "Cash received offline";
    payment.paymentForMonth = req.body.paymentForMonth || payment.paymentForMonth;
    await payment.save();

    const member = await User.findById(payment.memberId);
    if (member && member.status !== "active") {
      member.status = "active";
      await member.save();
    }

    if (member) {
      await notifyAdmins({
        type: "payment_completed",
        title: "Cash Payment Completed",
        message: `${member.name} cash payment was marked paid for ${payment.paymentForMonth || "the selected month"}.`,
        metadata: {
          paymentId: String(payment._id),
          memberId: String(member._id),
          month: payment.paymentForMonth || null,
        },
      });
    }

    res.json({ message: "Cash payment marked as paid", payment });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to mark cash payment", error: error.message });
  }
};

export const getMonthlyReport = async (req: Request, res: Response): Promise<void> => {
  try {
    const { year, month } = req.query;
    const currentDate = new Date();
    const targetYear = year ? Number.parseInt(year as string, 10) : currentDate.getFullYear();
    const targetMonth = month ? Number.parseInt(month as string, 10) - 1 : currentDate.getMonth();

    const startDate = new Date(targetYear, targetMonth, 1);
    const endDate = new Date(targetYear, targetMonth + 1, 0, 23, 59, 59);

    const [payments, monthlySummary, annualSummary, monthlyBreakdown] = await Promise.all([
      Payment.find({
        date: { $gte: startDate, $lte: endDate },
        status: "completed",
      }).populate("memberId", "name email sport"),

      Payment.aggregate([
        {
          $match: {
            date: { $gte: startDate, $lte: endDate },
            status: "completed",
          },
        },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: "$amount" },
            totalPayments: { $sum: 1 },
            avgPayment: { $avg: "$amount" },
          },
        },
      ]),

      Payment.aggregate([
        {
          $match: {
            date: {
              $gte: new Date(targetYear, 0, 1),
              $lte: new Date(targetYear, 11, 31, 23, 59, 59),
            },
            status: "completed",
          },
        },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: "$amount" },
            totalPayments: { $sum: 1 },
            avgPayment: { $avg: "$amount" },
          },
        },
      ]),

      Payment.aggregate([
        {
          $match: {
            date: {
              $gte: new Date(targetYear, 0, 1),
              $lte: new Date(targetYear, 11, 31, 23, 59, 59),
            },
            status: "completed",
          },
        },
        {
          $group: {
            _id: { $month: "$date" },
            revenue: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ]),
    ]);

    res.json({
      period: { year: targetYear, month: targetMonth + 1 },
      summary: monthlySummary[0] || { totalRevenue: 0, totalPayments: 0, avgPayment: 0 },
      annualSummary: annualSummary[0] || { totalRevenue: 0, totalPayments: 0, avgPayment: 0 },
      monthlyBreakdown,
      payments,
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to generate report", error: error.message });
  }
};

export const getReceipt = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const payment = await Payment.findById(req.params.id).populate(
      "memberId",
      "name email sport membershipType"
    );

    if (!payment) {
      res.status(404).json({ message: "Payment not found" });
      return;
    }

    const memberDoc = payment.memberId as unknown as { _id?: { toString(): string } };
    if (req.user?.role === "member" && memberDoc?._id?.toString() !== req.user.id) {
      res.status(403).json({ message: "Access denied. Insufficient permissions." });
      return;
    }

    res.json({
      receiptNumber: payment.receiptNumber,
      member: payment.memberId,
      amount: payment.amount,
      date: payment.date,
      method: payment.method,
      status: payment.status,
      description: payment.description,
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to generate receipt", error: error.message });
  }
};

export const getPrediction = async (_req: Request, res: Response): Promise<void> => {
  try {
    const [attendance, profit] = await Promise.all([predictAttendance(), predictClubProfit()]);
    res.json({ attendance, profit });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to generate prediction", error: error.message });
  }
};
