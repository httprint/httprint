function uploadFile() {
    let uploadField = document.getElementById("upload-file");
    let printButton = document.getElementById("print-btn");
    if (!uploadField.files.length) {
        addMessage("Choose a file first", false);
        return;
    }
    let fileName = uploadField.files[0].name;
    let formData = new FormData();

    formData.append("file", uploadField.files[0]);
    formData.append("copies", document.getElementById("copies").value);
    formData.append("sides", document.getElementById("sides").value);
    formData.append("media", document.getElementById("media").value);
    formData.append("color", document.getElementById("color").value);

    printButton.disabled = true;
    printButton.querySelector("span").textContent = "Sending...";
    fetch("/api/upload", {method: "POST", body: formData})
        .then(function(response) {
            return response.json();
        })
        .then(function(reply) {
            if (reply && !reply.error) {
                addMessage(reply.message || "File sent to printer", true, fileName);
                uploadField.value = null;
                document.getElementById("file-label").textContent = "Drop a file here";
                document.getElementById("copies").value = 1;
            } else {
                addMessage(reply.message || "Unable to print file", false);
            }
        })
        .catch(function(err) {
            console.log(err);
            addMessage("Failed to send file", false);
        })
        .finally(function() {
            printButton.disabled = false;
            printButton.querySelector("span").textContent = "Send to printer";
        });
}

function addMessage(text, success, fileName) {
    let log = document.getElementById("message-log");
    let emptyMessage = log.querySelector(".empty-message");
    if (emptyMessage) {
        emptyMessage.remove();
    }
    let entry = document.createElement("p");
    entry.className = "message-entry" + (success ? "" : " error");
    entry.title = text;
    let marker = document.createElement("span");
    marker.className = "message-marker";
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = success ? "✓" : "×";
    let messageText = document.createElement("span");
    messageText.className = "message-text";
    if (success) {
        let codeMatch = text.match(/code:\s*([0-9-]+)/i);
        messageText.textContent = (codeMatch ? codeMatch[1] : "Ready") + " · " + fileName;
    } else {
        messageText.textContent = text;
    }
    let deleteButton = document.createElement("button");
    deleteButton.className = "message-delete";
    deleteButton.type = "button";
    deleteButton.title = "Remove message";
    deleteButton.setAttribute("aria-label", "Remove message");
    deleteButton.textContent = "×";
    deleteButton.addEventListener("click", function() {
        entry.remove();
        updateMessageCount();
    });
    entry.append(marker, messageText, deleteButton);
    log.prepend(entry);
    updateMessageCount();
}

function updateMessageCount() {
    let count = document.querySelectorAll(".message-entry").length;
    document.getElementById("message-count").textContent = count + (count === 1 ? " message" : " messages");
}


document.addEventListener("DOMContentLoaded", function(event) {
    let pbutton = document.getElementById("print-btn");
    let uploadField = document.getElementById("upload-file");
    let dropzone = document.querySelector(".dropzone");
    uploadField.addEventListener("change", function() {
        document.getElementById("file-label").textContent = uploadField.files.length ? uploadField.files[0].name : "Drop a file here";
    });
    ["dragenter", "dragover"].forEach(function(eventName) {
        dropzone.addEventListener(eventName, function(event) { event.preventDefault(); dropzone.classList.add("is-dragging"); });
    });
    ["dragleave", "drop"].forEach(function(eventName) {
        dropzone.addEventListener(eventName, function(event) { event.preventDefault(); dropzone.classList.remove("is-dragging"); });
    });
    dropzone.addEventListener("drop", function(event) {
        if (event.dataTransfer.files.length) { uploadField.files = event.dataTransfer.files; uploadField.dispatchEvent(new Event("change")); }
    });
    pbutton.addEventListener("click", function(event) {
        uploadFile();
    });
});
