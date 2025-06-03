const IncomeSchema = require("../models/IncomeModel");

exports.addIncome = async (req, res) => {
    const { title, amount, category, description, date } = req.body;

    try {
        // validations
        if (!title || !category || !description || !date) {
            return res.status(400).json({ message: 'All fields are required!' });
        }
        if (amount <= 0 || typeof amount !== 'number') {
            return res.status(400).json({ message: 'Amount must be a positive number!' });
        }

        const income = new IncomeSchema({
            title,
            amount,
            category,
            description,
            date,
            userId: req.user._id  // Link to logged-in user
        });

        await income.save();
        res.status(200).json({ message: 'Income Added' });
        console.log(income);
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};

exports.getIncomes = async (req, res) => {
    try {
        const incomes = await IncomeSchema.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json(incomes);
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};

exports.deleteIncome = async (req, res) => {
    const { id } = req.params;

    try {
        const income = await IncomeSchema.findOneAndDelete({ _id: id, userId: req.user._id });

        if (!income) {
            return res.status(404).json({ message: 'Income not found or not authorized' });
        }

        res.status(200).json({ message: 'Income Deleted' });
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
};
