import fs from 'fs';
import path from 'path';
import inquirer from 'inquirer';

const distributionFilePath = path.join( '../data/distribution.json');

function checkDuplicateAddresses(jsonData) {
    const uniqueAddresses = new Set();
    const duplicateAddresses = new Set();

    jsonData.forEach((item) => {
        if (uniqueAddresses.has(item.address)) {
            duplicateAddresses.add(item.address);
        } else {
            uniqueAddresses.add(item.address);
        }
    });

    return Array.from(duplicateAddresses);
}

function mergeDuplicates(data, address) {
    const mergedData = data.filter((item) => item.address !== address);
    const duplicates = data.filter((item) => item.address === address);

    const mergedItem = duplicates.reduce((acc, current) => {
        acc.headstash = acc.headstash.concat(current.headstash);
        return acc;
    }, { address, headstash: [] });

    const mergedHeadstash = mergedItem.headstash.reduce((acc, current) => {
        const existingIndex = acc.findIndex((item) => item.contract === current.contract);
        if (existingIndex !== -1) {
            acc[existingIndex].amount = (parseInt(acc[existingIndex].amount) + parseInt(current.amount)).toString();
        } else {
            acc.push(current);
        }
        return acc;
    }, []);

    mergedItem.headstash = mergedHeadstash;

    mergedData.push(mergedItem);
    return mergedData;
}

function removeDuplicates(data, address) {
    const filteredData = data.filter((item) => item.address !== address);
    return filteredData;
}

fs.readFile(distributionFilePath, 'utf8', async (err, data) => {
    if (err) {
        console.error(err);
        return;
    }

    try {
        const jsonData = JSON.parse(data);
        const duplicateAddresses = checkDuplicateAddresses(jsonData);

        if (duplicateAddresses.length > 0) {
            console.log("Duplicate addresses found:");
            console.log(duplicateAddresses);

            let updatedData = jsonData;

            for (const address of duplicateAddresses) {
                let duplicates = updatedData.filter((item) => item.address === address);

                while (duplicates.length > 1) {
                    console.log(`Found ${duplicates.length} duplicates for address ${address}:`);
                    duplicates.forEach((item, index) => {
                        console.log(`${index + 1}. ${JSON.stringify(item)}`);
                    });

                    if (duplicates.length === 2) {
                        const answer = await inquirer.prompt({
                            type: 'list',
                            name: 'action',
                            message: `What do you want to do with the duplicate address ${address}?`,
                            choices: ['Merge', 'Remove one'],
                        });

                        if (answer.action === 'Merge') {
                            updatedData = mergeDuplicates(updatedData, address);
                            console.log(`Merged duplicate address ${address}`);
                            break;
                        } else if (answer.action === 'Remove one') {
                            const removeAnswer = await inquirer.prompt({
                                type: 'list',
                                name: 'removeIndex',
                                message: `Which one do you want to remove?`,
                                choices: duplicates.map((item, index) => `${index + 1}. ${JSON.stringify(item)}`),
                            });

                            const removeIndex = parseInt(removeAnswer.removeIndex.split('.')[0]) - 1;
                            updatedData = updatedData.filter((item, index) => item.address !== address || index !== updatedData.findIndex((i) => i.address === address && JSON.stringify(i) === JSON.stringify(duplicates[removeIndex])));
                            duplicates.splice(removeIndex, 1);
                        }
                    } else {
                        const answer = await inquirer.prompt({
                            type: 'checkbox',
                            name: 'removeIndexes',
                            message: `Which ones do you want to remove?`,
                            choices: duplicates.map((item, index) => `${index + 1}. ${JSON.stringify(item)}`),
                        });

                        const removeIndexes = answer.removeIndexes ? answer.removeIndexes.map((item) => parseInt(item.split('.')[0]) - 1) : [];

                        if (removeIndexes.length > 0) {
                            const itemsToRemove = removeIndexes.map((index) => duplicates[index]);
                            updatedData = updatedData.filter((item) => !itemsToRemove.includes(item));
                            duplicates = duplicates.filter((item) => !itemsToRemove.includes(item));
                        } else {
                            const removeAnswer = await inquirer.prompt({
                                type: 'list',
                                name: 'action',
                                message: `What do you want to do with the remaining duplicates for address ${address}?`,
                                choices: ['Merge', 'Remove all'],
                            });

                            if (removeAnswer.action === 'Remove all') {
                                updatedData = removeDuplicates(updatedData, address);
                            }
                        }

                        if (duplicates.length > 1) {
                            const mergeAnswer = await inquirer.prompt({
                                type: 'list',
                                name: 'action',
                                message: `What do you want to do with the remaining duplicates for address ${address}?`,
                                choices: ['Merge', 'Remove one'],
                            });

                            if (mergeAnswer.action === 'Merge') {
                                updatedData = mergeDuplicates(updatedData, address);
                                console.log(`Merged duplicate address ${address}`);
                                break;
                            }
                        }
                    }
                }
            }

            fs.writeFile(distributionFilePath, JSON.stringify(updatedData, null, 2), (err) => {
                if (err) {
                    console.error(err);
                    return;
                }
                console.log('Updated data saved to distribution.json');
            });
        } else {
            console.log("No duplicate addresses found.");
        }
    } catch (err) {
        console.error(err);
    }
});